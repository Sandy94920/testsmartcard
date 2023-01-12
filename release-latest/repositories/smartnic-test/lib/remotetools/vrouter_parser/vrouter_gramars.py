from parsimonious.grammar import Grammar

# looks for ipv4 or ipv6 address
ip_regex = ('~"((?:[0-9]{1,3}\.){3}[0-9]{1,3}|'             # noqa: W605
            '(?:[0-9a-fA-F]{0,4}\:){4}[0-9a-fA-F]{0,4})"')  # noqa: W605

vrouter_flows_grammar = Grammar(
    fr"""
    expr            = any_but_e_line entries_line flows other*

    entries_line    = ws title created added deleted changed processed used ws
    title           = "Entries:" ws
    created         = ~".*Created" ws number ws
    added           = ~".*Added" ws number ws
    deleted         = ~".*Deleted" ws number ws
    changed         = ~".*Changed" ws number ws
    processed       = ~".*Processed" ws number ws
    used            = ~".*Used\s+Overflow\s+entries" ws number ws

    flows           = flow_entry*
    flow_entry      = flow_info flow_options
    flow_info       = any_but_index index address any_but_proto proto
                      address
    flow_options    = any_but_lpar "(" key_vals ")"
    address         = any_but_ip ip ws ":" ws port
    key_vals        = key_val*
    key_val         = any_but_keys keys
    keys            = gen/knh/action/flags/tcp/qos/snh/stats/mirror_index/
                      sport/ttl/sinfo
    gen             = "Gen:" ws number
    knh             = "K(nh):" ws number
    action          = "Action:" ws any_but_comma
    flags           = "Flags:" ws any_but_comma
    tcp             = "TCP:" ws any_but_comma
    qos             = "QOS:" ws number
    snh             = "S(nh):" ws number
    stats           = "Stats:" ws stats_data
    mirror_index    = "Mirror" ws "Index" ws ":" ws optional_number
    sport           = "SPort" ws number
    ttl             = "TTL" ws number
    sinfo           = "Sinfo" ws any_but_rpar

    index           = number ws "<=>" ws number
    proto           = proto_number ws "(" proto_number ")"

    number          = ~"-?\d+"
    optional_number = ~"\d*"
    proto_number    = ~"\d{{1,3}}"
    ws              = ~"\s*"
    ip              = {ip_regex}
    port            = ~"\d{{1,5}}"
    stats_data      = ~"\d+\/\d+"

    any_but_comma   = ~"[^\,]*"
    any_but_rpar    = ~"[^\)]*"
    any_but_lpar    = ~"[^\(]*"
    any_but_e_line  = (!entries_line (~"." / ws))*
    any_but_sep     = ~"[\-{{3,}}]*"
    any_but_index   = (!index (~"." / ws))*
    any_but_ip      = (!ip (~"." / ws))*
    any_but_proto   = (!proto (~"." / ws))*
    any_but_keys    = (!(keys / ")") (~"." / ws))*
    other           = ~".*" ws
    """)