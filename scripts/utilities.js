/* This file contains utilities to support data-conversion towards tplay */

var csv = require('csv');
var bs = require('binary-search');


function readNetwork2AsDatabase(file, callback) {
    csv()
        .from.path(file)
        .to.array(function(network2as) {
            var asHolder = {}
            network2as.forEach(function (asRecord) {
                var info = parseAsString(asRecord[2]);
                asHolder[info.asn] = info.holder;
            })
            callback(network2as, asHolder);
        })
}


function ipv4_to_integer(dot)  {
    var d = dot.split('.')
    return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3])
}


function integer_to_ipv4(num) {
    var d = num % 256;
    for (var i = 3; i > 0; i--)
    {
        num = Math.floor(num / 256)
        d = num % 256 + '.' + d
    }
    return d
}


function parseAsString(asString) {
    var firstSpace = asString.indexOf(' ')
    var asn = asString.substring(2, firstSpace)
    var holder = asString.substring(firstSpace + 1)
    return { asn: asn, holder: holder }
}


function mapIp2As(map, ip, network2as) {

    if (ip in map)
        return

    var record = {
        address: ip,
        as_numbers: []
    }

    var index = bs(network2as, ip, function(network, ip) {
        var ipInt = ipv4_to_integer(ip)
        if (ipInt < network[0])
            return 1
        else if (ipInt > network[1])
            return -1
        else
            return 0
    });

    if (index >= 0) {
        var asString = network2as[index][2]
        record.as_numbers.push(parseAsString(asString))
    }

    map[ip] = record
}


function resolveAllIpToAs(traceroutes, network2asFile, callback) {

    readNetwork2AsDatabase(network2asFile, function (network2as) {
        var ip2as = traceroutes.reduce(function (result, traceroute) {
                traceroute.hops.forEach(function (hop) {
                    hop.replies.forEach(function (reply) {
                        mapIp2As(result, reply.ip, network2as)
                    })
                })
                return result
            },
            {})

        var ip2asArray = []
        for (ip in ip2as)
            ip2asArray.push(ip2as[ip])

        var asMap = {}
        network2as.forEach(function (asRecord) {
            var info = parseAsString(asRecord[2]);
            asMap[info.asn] = info.holder
        })

        callback(ip2asArray, asMap)
    })
}


module.exports = {
    resolveAllIpToAs : resolveAllIpToAs,
    readNetwork2AsDatabase : readNetwork2AsDatabase,
    parseAsString : parseAsString,
    mapIp2As : mapIp2As,
    ipv4_to_integer : ipv4_to_integer
};