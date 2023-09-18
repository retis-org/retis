from testlib import Retis, assert_events_present


def test_nft_icmp_policy_drop(two_ns_simple):
    ns = two_ns_simple
    retis = Retis()
    NFT_RULESET = """
    table inet nft_test {
        chain input_filter {
            type filter hook input priority 0; policy drop;
            jump input_ind1_hook
            jump input_ind2_hook
        }

        chain input_ind1_hook {
        }

        chain input_ind2_hook {
        }
    }
    """

    print(ns.run("ns0", "nft", NFT_RULESET))
    print(ns.run("ns1", "nft", NFT_RULESET))

    retis.collect(
        "-c",
        "nft",
        "-f",
        "net 10.0.42.0/30 and icmp",
        "--nft-verdicts",
        "all",
        "--allow-system-changes",
    )
    # policy drop
    print(ns.run_fail("ns1", "ping", "-c", "1", "-W", "0.5", "10.0.42.1"))

    retis.stop()

    expected_events = [
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "rule_handle": 4,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "jump",
                "verdict_chain_name": "input_ind1_hook",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 2,
                "chain_name": "input_ind1_hook",
                "policy": False,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "continue",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "rule_handle": 5,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "jump",
                "verdict_chain_name": "input_ind2_hook",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 3,
                "chain_name": "input_ind2_hook",
                "policy": False,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "continue",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "continue",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": True,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "drop",
            },
        },
    ]

    events = retis.events()
    assert_events_present(events, expected_events)


def test_nft_icmp_rule_accept(two_ns_simple):
    ns = two_ns_simple
    retis = Retis()

    NFT_RULESET = """
    table inet nft_test {
        chain input_filter {
            type filter hook input priority 0; policy drop;
            jump input_ind1_hook
            jump input_ind2_hook
        }

        chain input_ind1_hook {
        }

        chain input_ind2_hook {
            ip saddr 10.0.42.1 icmp type echo-request accept
            ip saddr 10.0.42.2 icmp type echo-reply accept
        }
    }
    """

    print(ns.run("ns0", "nft", NFT_RULESET))
    print(ns.run("ns1", "nft", NFT_RULESET))

    retis.collect(
        "-c",
        "nft",
        "-f",
        "net 10.0.42.0/30 and icmp",
        "--nft-verdicts",
        "all",
        "--allow-system-changes",
    )

    # rule verdict (accept)
    print(ns.run("ns0", "ping", "-c", "1", "10.0.42.2"))
    retis.stop()

    expected_events = [
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "rule_handle": 4,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "jump",
                "verdict_chain_name": "input_ind1_hook",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 2,
                "chain_name": "input_ind1_hook",
                "policy": False,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "continue",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "rule_handle": 5,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "jump",
                "verdict_chain_name": "input_ind2_hook",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 3,
                "chain_name": "input_ind2_hook",
                "policy": False,
                "rule_handle": 6,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "accept",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "rule_handle": 4,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "jump",
                "verdict_chain_name": "input_ind1_hook",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 2,
                "chain_name": "input_ind1_hook",
                "policy": False,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "continue",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 1,
                "chain_name": "input_filter",
                "policy": False,
                "rule_handle": 5,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "jump",
                "verdict_chain_name": "input_ind2_hook",
            },
        },
        {
            "common": {
                "task": {
                    "comm": "ping",
                },
            },
            "kernel": {"probe_type": "kprobe", "symbol": "__nft_trace_packet"},
            "nft": {
                "chain_handle": 3,
                "chain_name": "input_ind2_hook",
                "policy": False,
                "rule_handle": 7,
                "table_handle": 1,
                "table_name": "nft_test",
                "verdict": "accept",
            },
        },
    ]

    events = retis.events()
    assert_events_present(events, expected_events)
