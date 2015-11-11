/*
 * Convert traceroute data from RIPE Atlas' format to TPlay's format.
 * Input data must be in BSON format, i.e. one JSON object per line.
 * Input data can refer to one or several Atlas measurements.
 * Note that the structure of the input data can vary depending on the firmware version of the probes (see the "fw" field).
 *
 * usage:
 *     node atlas2tplay.js atlas_traceroutes.bson GeoIPASNum.csv [--probe-cache=probe_cache.json] [--skip-validation]
 * output:
 *     In the same directory as the input Atlas file, the following files are produced.
 *     traceroutes.bson
 *     measurement.bson
 *     ip2as.bson
 *     probe-metadata.bson
 *     probe_cache.json (update the input one instead, if provided)
 */

var validate = require('jsonschema').validate;
var request = require('request');
var LineByLine = require('n-readlines');
var fs = require("fs");
var utilities = require("./utilities.js");
var argparse = require('minimist');
var path = require("path");


var schema_v4460 =
{
    title: "A subset of the RIPE Atlas' traceroute data format (v4460)",
    type: "object",
    properties:
    {
        af: { enum: [4, 6], description: "IP address family, 4 or 6", required: true },
        src_addr: { type: "string", description: "IP address of the probe", required: true },
        dst_addr: { type: "string", minLength: 1, description: "IP address of the destination", required: true },
        timestamp: { type: "integer", description: "UNIX timestamp for start of measurement", required: true },
        endtime: { type: "integer", description: "UNIX timestamp for end of measurement", required: true },
        from: { type: "string", description: "IP address of the probe as know by controller. Often the network where the probe is located", required: true },
        fw: { type: "integer", description: "Firmware version of the probe", required: true },
        msm_id: { type: "integer", description: "Measurement ID", required: true },
        prb_id: { type: "integer", description: "Probe ID", required: true },

        result:
        {
            type: "array",
            description: "Traceroute content as a sequence of hops. In case of error, num items = 1",
            required: true,
            minItems: 1,
            items:
            {
                type: "object",
                description: "Hop object. In case of error, it has the 'error' property instead of 'result'",
                properties:
                {
                    hop: { type: "integer", description: "Position of this hop in the traceroute", required: true },
                    result:
                    {
                        type: "array",
                        description: "Sequence of three replies from this hop",
                        items:
                        {
                            type: "object",
                            description: "Single reply from this hop. In case of null, the only property is 'x': '*'",
                            properties:
                            {
                                from: { type: "string", description: "IP address that sent the reply" },
                                rtt: { type: "number", description: "Round-trip time" },
                                x: { enum: ["*", undefined], description: "No-reply from the hop" }
                            }
                        }
                    },
                    error: { type: "string", description: "Message describing the error" }
                }
            }
        }
    }
};


var probe_metadata_schema =
{
    title: "A subset of RIPE's Atlas data format for describing probes' metadata",
    type: "object",
    properties: {
        objects: {
            type: "array",
            description: "Each object describes a probe",
            required: true,
            minItems: 1,
            items: {
                type: "object",
                description: "Metadata of a probe. It is a static snapshot, IP addresses and prefixes may be different from what is in traceroutes",
                properties: {
                    address_v4: { type: ["string", null] },
                    address_v6: { type: ["string", null] },
                    asn_v4: { type: ["integer", null], required: true },
                    asn_v6: { type: ["integer", null], required: true },
                    country_code: { type: "string", required: true },
                    latitude: { type: "number", required: true },
                    longitude: { type: "number", required: true },
                    prefix_v4: { type: ["string", null], required: true },
                    prefix_v6: { type: ["string", null], required: true }
                }
            }
        }
    }
}


function convertTraceroute(measurementData, skipValidation) {

    if (!skipValidation) {
        var val = validate(measurementData, schema_v4460);
        if (val.errors.length > 0) {
            console.error("-------");
            console.error("WARNING: skipping malformed instance, ", val.errors[0].stack);
            console.error(JSON.stringify(val.instance));
            console.error("-------");
            return null;
        }
    }

    var measurement = {};

    var targetIp = null;
    var lastHopContainsTargetIp = false;

    // fields common to different firmwares
    measurement["prb_id"] = measurementData["prb_id"];
    measurement["msm_id"] = measurementData["msm_id"];
    measurement["startTimestamp"] = measurementData["timestamp"];
    measurement["target"] = measurementData["dst_addr"];
    measurement["hops"] = [];

    // early firmware
    if(measurementData["fw"] < 4400) {

        measurement["endTimestamp"] = null;
        measurement["error"] = false;

        measurementData["result"].split("NEWLINE").forEach(function(hop) {

            var fields;
            hop = hop.trim();

            if(hop.length == 0) {
                return;
            }

            if(hop.indexOf("traceroute") >= 0) {
                fields = hop.split(" "); // "[traceroute, to, XXX, ...]"
                targetIp = fields[2];
                return;
            }

            fields = hop.split("  "); // 2-space-separated fields in standard traceroute output
            var ipMap = {}; // temporary map to store RTTs associated with each IP
            var lastIp = ""; // last seen IP
            var ipCount = 0; // unique IPs seen at this hop
            fields.forEach(function(field, index) {
                if(index == 0) // hop count
                    return;
                if(field.indexOf("!") >= 0 || field.indexOf("*") >= 0) // errors or no-answers
                    return;
                if(field.indexOf("ms") < 0) { // this must be an IP
                    lastIp = field;
                    if(ipMap[lastIp] == undefined) {
                        ipMap[lastIp] = [];
                        ipCount++;
                    }
                }
                else { // round-trip time associated with an IP (es. "123 ms")
                    ipMap[lastIp].push(field.split(" ")[0] * 1.); // (es. 123)
                }
            });

            var hopObj = {};
            hopObj["noAnswer"] = (ipCount == 0);
            hopObj["replies"] = [];
            for(lastIp in ipMap) {
                hopObj["replies"].push({
                    "ip": lastIp,
                    "rtt": ipMap[lastIp]
                });
            }

            measurement["hops"].push(hopObj);
        });



    }

    // late firmware
    else {
        if(measurementData["result"] == undefined) {
            measurement["error"] = true;
        }
        else {

            targetIp = measurementData["addr"] || measurementData["dst_addr"];

            measurement["endTimestamp"] = measurementData["endtime"];
            measurementData["result"].forEach(function(hop) {
                if(hop["error"] != undefined)
                    return;

                var ipMap = {}; // temporary map to store RTTs associated with each IP
                var lastIp; // last seen IP
                var ipCount = 0; // unique IPs seen at this hop

                hop["result"].forEach(function(reply) {

                    if(reply.x != undefined)
                        return;

                    var ip = reply.from;
                    if(ipMap[ip] == undefined) {
                        ipCount++;
                        ipMap[ip] = [];
                    }

                    ipMap[ip].push(reply.rtt);

                });

                var hopObj = {};
                hopObj["noAnswer"] = (ipCount == 0);
                hopObj["replies"] = [];
                for(lastIp in ipMap) {
                    hopObj["replies"].push({
                        "ip": lastIp,
                        "rtt": ipMap[lastIp]
                    });
                }

                measurement["hops"].push(hopObj);

            });



        }

    }

    var lastHopReplies = undefined;

    if(measurement["hops"] != undefined && measurement["hops"].length > 0) {
        lastHopReplies = measurement["hops"][measurement["hops"].length - 1].replies;
        if(lastHopReplies != undefined) {
            lastHopReplies.forEach(function(reply) {
                if(targetIp != null && reply.ip == targetIp) {
                    lastHopContainsTargetIp = true;
                }
            });
        }
    }


    if(!lastHopContainsTargetIp) {
        measurement["error"] = true;
    }

    return measurement;
}


function getProbeMetadata(prb_id, asHolder, skipValidation, callback) {
    var url = "https://atlas.ripe.net/api/v1/probe/?format=json&id=" + prb_id

    request(url, function(err, response, body) {
        var data = JSON.parse(body);
        var result;

        if (!skipValidation) {
            var val = validate(data, probe_metadata_schema);
            if (val.errors.length > 0) {
                console.error("-------");
                console.error("WARNING: skipping malformed probe metadata, ", val.errors[0].stack);
                console.error(JSON.stringify(val.instance));
                console.error("-------");
                result = {};
                callback(result);
                return;
            }
        }

        var data = data.objects[0];

        result = {
            prb_id : parseInt(prb_id),
            v4_as : data.asn_v4,
            v4_as_holder : null,
            v4_ip: data.address_v4,
            v4_prefix: data.prefix_v4,
            v6_as : data.asn_v6,
            v6_as_holder : null,
            v6_ip: data.address_v6,
            v6_prefix: data.prefix_v6,
            lat : data.latitude,
            lon : data.longitude,
            locations : []
        }

        if (result.v4_as in asHolder && result.v6_as in asHolder) {
            result.v4_as_holder = asHolder[result.v4_as];
            result.v6_as_holder = asHolder[result.v6_as];
        } else if (result.v4_as in asHolder) {
            result.v4_as_holder = asHolder[result.v4_as];
        } else if (result.v6_as in asHolder) {
            result.v6_as_holder = asHolder[result.v6_as];
        } else {
            console.error("-------");
            console.error("WARNING: no AS holder info could be found for probe");
            console.error(JSON.stringify(result));
            console.error("-------");
            result.v4_as_holder = "UNKNOWN HOLDER FOR AS" + result.v4_as;
            result.v6_as_holder = "UNKNOWN HOLDER FOR AS" + result.v6_as;
        }

        callback(result);
    })
}


function getMeasurementsInfo(traceroute, measurementMap) {

    var msm_id = traceroute.msm_id;

    if (!(msm_id in measurementMap)) {
        measurementMap[msm_id] = {
            msm_id: msm_id,
            address: traceroute.target,
            description: "Measurement " + msm_id,
            protocol: 4,
            startTimestamp: Number.POSITIVE_INFINITY,
            endTimestamp: -1
        }
    }

    if (traceroute.target != measurementMap[msm_id].address) {
        console.error(
            "Inconsistent input data, found more than one target address: ",
            measurementMap[msm_id].address,
            traceroute.target);
        process.exit(1);
    }

    if (traceroute.startTimestamp < measurementMap[msm_id].startTimestamp)
        measurementMap[msm_id].startTimestamp = traceroute.startTimestamp;

    if (traceroute.endTimestamp > measurementMap[msm_id].endTimestamp)
        measurementMap[msm_id].endTimestamp = traceroute.endTimestamp;
}


// Main code

var args = argparse(process.argv.slice(2));
var traceroutesFile = args._[0];
var outputDir = path.dirname(traceroutesFile);
var network2asFile = args._[1];
var probeMetadataCacheFile = args["probe-cache"];
var skipValidation = args["skip-validation"];

var t0, t1, t2;

// Read the given probe metadata cache file, if provided
var probeMetadata;
if (probeMetadataCacheFile !== undefined) {
    probeMetadata = JSON.parse(fs.readFileSync(probeMetadataCacheFile));
} else {
    probeMetadataCacheFile = path.join(outputDir, "probe_cache.json");
    probeMetadata = {};
}

// Read the network -> AS file in CSV format
console.error("Loading the network2as database...");
t0 = t1 = (new Date()).getTime();
utilities.readNetwork2AsDatabase(network2asFile, function (network2as, asHolder) {

    t2 = (new Date()).getTime();
    console.error("\tdone " + ((t2 - t1) / 1000) + " s");

    var measurementMap = {};
    var probeIds = {};
    var ip2as = {};

    console.error("Scanning input traceroutes...");
    t1 = (new Date()).getTime();

    var outputTraceroute = fs.openSync(path.join(outputDir, "traceroute.bson"), 'w');
    // Note: each input line must fit in a "readChunk" bytes long buffer, or we get a corrupted JSON
    var lineReader = new LineByLine(traceroutesFile, {'readChunk': 1048576, 'newLineCharacter': '\n'}); 

    // Scan the input file line by line (each is a traceroute)
    var line;
    var tracerouteCounter = 0;
    while (line = lineReader.next()) {

        var atlasTracerouteJson = line.toString("utf8");
        var atlasTraceroute = JSON.parse(atlasTracerouteJson);
        var tplayTraceroute = convertTraceroute(atlasTraceroute, skipValidation);
        if (tplayTraceroute == null)
            continue;

        // Collect encountered probe ids
        probeIds[tplayTraceroute.prb_id] = true;

        // Collect encountered measurement info
        getMeasurementsInfo(tplayTraceroute, measurementMap);

        // Map each encountered ip to its AS
        tplayTraceroute.hops.forEach(function (hop) {
            hop.replies.forEach(function (reply) {
                utilities.mapIp2As(ip2as, reply.ip, network2as);
            })
        })

        // Write output for "traceroute"
        fs.writeSync(outputTraceroute, JSON.stringify(tplayTraceroute) + "\n");

        tracerouteCounter++;
        if (tracerouteCounter % 1000 == 0) {
            t2 = (new Date()).getTime();
            console.error("\t" + tracerouteCounter + " converted " + ((t2 - t1) / 1000) + " s");
        }
    }

    fs.closeSync(outputTraceroute);

    t2 = (new Date()).getTime();
    console.error("\tdone " + ((t2 - t1) / 1000) + " s");

    console.error("Writing measurement and ip2as data...");
    t1 = (new Date()).getTime();

    // Write output for "measurement"
    var outputMeasurement = fs.openSync(path.join(outputDir, "measurement.bson"), 'w');
    for (var msm_id in measurementMap)
        fs.writeSync(outputMeasurement, JSON.stringify(measurementMap[msm_id]) + "\n");
    fs.closeSync(outputMeasurement);

    // Write output for "ip2as"
    var outputIp2as = fs.openSync(path.join(outputDir, "ip2as.bson"), 'w');
    for (var ip in ip2as)
        fs.writeSync(outputIp2as, JSON.stringify(ip2as[ip]) + "\n");
    fs.closeSync(outputIp2as);

    t2 = (new Date()).getTime();
    console.error("\tdone " + ((t2 - t1) / 1000) + " s");

    console.error("Downloading probe metadata from Atlas...");
    t1 = (new Date()).getTime();

    // Get metadata for every encountered probe, and write output for "probe-metadata"
    var outputProbeMetadata = fs.openSync(path.join(outputDir, "probe-metadata.bson"), 'w');
    var probes = Object.keys(probeIds);
    var probeCounter = 0;

    // When metadata for a probe is obtained,
    // write it to the probe-metadata file, and check whether it was the last probe.
    var onProbeMetadata = function(prb_id, metadata) {
        fs.writeSync(outputProbeMetadata, JSON.stringify(metadata) + "\n");
        probeCounter++;
        if (probeCounter % 100 == 0) {
            t2 = (new Date()).getTime();
            console.error("\t" + probeCounter + "/" + probes.length + " " + ((t2 - t1) / 1000) + " s");
        }
        if (probeCounter == probes.length) {
            // This was the last probe
            fs.closeSync(outputProbeMetadata);
            t2 = (new Date()).getTime();
            console.error("\tdone " + ((t2 - t1) / 1000) + " s");
            console.error("total " + ((t2 - t0) / 1000) + " s");
            // Write the probe cache file with updated data.
            fs.writeFileSync(probeMetadataCacheFile, JSON.stringify(probeMetadata, null, 4));
        }
    }

    // Scan all collected probe ids
    probes.forEach(function (prb_id) {
        // Do we already know this probe?
        if (prb_id in probeMetadata) {
            // Yes, we do. Get the metadata from the cache.
            // Note: all iterations in this branch are executed before
            // the asynchronous ones.
            onProbeMetadata(prb_id, probeMetadata[prb_id]);
        } else {
            // No. (Asynchronously) download its metadata from Atlas,
            // and update our cache.
            getProbeMetadata(prb_id, asHolder, skipValidation, function (metadata) {
                probeMetadata[prb_id] = metadata;
                onProbeMetadata(prb_id, metadata);
            });
        }
    });
});
