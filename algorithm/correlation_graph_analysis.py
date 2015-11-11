
import networkx

unpopiudimezzora=60*60/2*1.2
dieciminuti=60*10



def analyse_filtered_events(pairs):

    graph = networkx.Graph()

    for pair in pairs:

        e1=pair["event1"]
        e2=pair["event2"]
        
        n1=(e1["msm_id"], e1["prb_id"])
        n2=(e2["msm_id"], e2["prb_id"])

        if graph.has_node(n1):
            if graph.node[n1]["fromtimestamp"] != e1["timestamp"]:
                continue
        else:
            graph.add_node(n1, fromtimestamp= e1["timestamp"])
            
        if graph.has_node(n2):
            if graph.node[n2]["fromtimestamp"] != e2["timestamp"]:
                continue
        else:
            graph.add_node(n2, fromtimestamp= e2["timestamp"])

        graph.add_edge(n1,n2)
        
        
        if graph.node[n1].has_key('from_rtt'):
            assert graph.node[n1]["from_rtt"] == e1['from_rtt']
            assert graph.node[n1]["to_rtt"]   == e1['to_rtt']

        if graph.node[n2].has_key('from_rtt'):
            assert graph.node[n2]["from_rtt"] == e2['from_rtt']
            assert graph.node[n2]["to_rtt"]   == e2['to_rtt']

        graph.node[n1]["from_rtt"] = e1['from_rtt']
        graph.node[n1]["to_rtt"]   = e1['to_rtt']
        graph.node[n2]["from_rtt"] = e2['from_rtt']
        graph.node[n2]["to_rtt"]   = e2['to_rtt']

    max_connected_component = [] if graph.size() == 0 else max(networkx.connected_components(graph), key=len)
    max_clique = [] if graph.size() == 0 else max(networkx.find_cliques(graph), key=len)

    msm_list_in_max_cc = map(lambda x: x[0], max_connected_component)
    prb_list_in_max_cc = map(lambda x: x[1], max_connected_component)

    most_common_msm_count_in_max_cc = 0 if len(msm_list_in_max_cc) == 0 else msm_list_in_max_cc.count(max(set(msm_list_in_max_cc), key=msm_list_in_max_cc.count))
    most_common_prb_count_in_max_cc = 0 if len(prb_list_in_max_cc) == 0 else prb_list_in_max_cc.count(max(set(prb_list_in_max_cc), key=prb_list_in_max_cc.count))

    msm_list_in_max_clique = map(lambda x: x[0], max_clique)
    prb_list_in_max_clique = map(lambda x: x[1], max_clique)

    most_common_msm_count_in_max_clique = 0 if len(msm_list_in_max_clique) == 0 else msm_list_in_max_clique.count(max(set(msm_list_in_max_clique), key=msm_list_in_max_clique.count))
    most_common_prb_count_in_max_clique = 0 if len(prb_list_in_max_clique) == 0 else prb_list_in_max_clique.count(max(set(prb_list_in_max_clique), key=prb_list_in_max_clique.count))

    HIGHVALUE=99999999
    LOWVALUE=-HIGHVALUE
    min_deltartt=HIGHVALUE
    max_deltartt=LOWVALUE
    sum_deltartt=0
    for n in max_clique:
        if not graph.node[n]['to_rtt'] or not graph.node[n]['from_rtt']:
            continue
        deltartt = graph.node[n]['to_rtt'] - graph.node[n]['from_rtt']
        min_deltartt=min(min_deltartt, deltartt)
        max_deltartt=max(max_deltartt, deltartt)
        sum_deltartt+=deltartt
    avg_deltartt= sum_deltartt/len(max_clique) if len(max_clique)>0 else 0
            
    return {
        "edge_count": len(graph.edges()),
        "node_count": len(graph.nodes()),
        "max_connected_component_size": len(max_connected_component),
        "max_clique_size": len(max_clique),
        "most_common_msm_count_in_max_cc": most_common_msm_count_in_max_cc,
        "most_common_prb_count_in_max_cc": most_common_prb_count_in_max_cc,
        "most_common_msm_count_in_max_clique": most_common_msm_count_in_max_clique,
        "most_common_prb_count_in_max_clique": most_common_prb_count_in_max_clique,
        "min_deltartt": min_deltartt if not min_deltartt == HIGHVALUE else 0,
        "max_deltartt": max_deltartt if not max_deltartt == LOWVALUE else 0,
        "avg_deltartt": avg_deltartt,
    }


def analyze_graph_with_sliding_window(info, window, step):

    start = info["tmin"]
    end = start + window

    graph_analysis = {
        "pre": [],
        "post": []
    }

    while start < info["tmax"]:
        graph_analysis["pre"].append({
            "start": start,
            "analysis": analyse_filtered_events(
                [i for i in info["pre"] if start <= i["event1"]["timestamp"] < end
                    and start <= i["event2"]["timestamp"] < end])
        })
        graph_analysis["post"].append({
            "start": start,
            "analysis": analyse_filtered_events(
                [i for i in info["post"] if start <= i["event1"]["timestamp"] < end
                    and start <= i["event2"]["timestamp"] < end])
        })
        start += step
        end = start + window

    return graph_analysis
