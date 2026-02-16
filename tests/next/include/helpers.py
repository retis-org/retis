import base64
import json
import sys

from scapy.all import Ether


def packet_to_json(raw_packet):
    p = Ether(base64.decodebytes(raw_packet.encode("ascii")))
    res = {}
    for line in p.show2(dump=True).split("\n"):
        if "###" in line:
            proto = line.strip("#[] ").lower()
            res[proto] = {}
        elif "=" in line:
            key, val = line.split("=", 1)
            res[proto][key.strip().lower()] = val.strip().lower()
    return res


def events_to_json(file):
    events = []
    with open(file) as f:
        for event in f.readlines():
            event = json.loads(event)

            if "packet" in event:
                event["parsed_packet"] = packet_to_json(event["packet"]["data"])

            events.append(event)
    return events


def assert_events_present(file, expected):
    events = events_to_json(file)

    idx = 0
    aliases = {}
    for ex_idx, ex in enumerate(expected):
        found = False
        # Find an event that matches
        for i in range(idx, len(events)):
            is_sub, reason = __is_subset(events[i], ex, aliases)
            if is_sub:
                print(
                    f"HIT: Event at index {i}\n"
                    f"   Event: {events[i]}\n"
                    f" matches expected at index {ex_idx}: \n"
                    f"   {ex}\n"
                    f"   Aliases: {aliases}"
                )
                found = True
                idx = i + 1
                break
            else:
                # Print the reason so it's easier to debug (if test fails)
                print(
                    f"MISS: Event at index {i}\n"
                    f"   Event {events[i]} \n"
                    f" did not match expected:"
                    f"   {ex}\n."
                    f"   Reason: {reason}."
                    f"   Aliases: {aliases}"
                )
        if not found:
            print(
                f"Failed to find expected event at index >= {idx}:"
                f"   Expected: {ex}\n"
                f"   Aliases: {aliases}\n"
                f"   Event list {json.dumps(events, indent=4)}"
            )
            sys.exit(1)


def __is_subset(superset, subset, aliases):
    """Recursively check if a dictionary is a subset of another one.

    Aliases are supported, if a value starts with '&' followed by an alias
    name, the value is stored in the provided hash table indexed by the alias
    name (no verification is made). If a value starts with '*' followed
    by an alias name, the value is retrieved from the aliases hash table
    and is checked. If a value starts with '!' followed by an alias name, the
    value is retrieved from the aliases hash table and is checked to make sure
    it does not match.

    E.g:
        > aliases = {}
        > __is_subset(
            {"foo": {"bar": "helloWorld"}, "baz": 42},
            {"foo": {"bar": "&myalias"}, "baz": 42},
            aliases)
        >> True, None
        > __is_subset(
            {"baz": "helloWorld"},
            {"baz": "*myalias"},
            aliases)
        >> True, None
    """
    for key, value in subset.items():
        if key not in superset:
            return (
                False,
                f"{subset} is not a subset of {superset}." f" key {key} is not present",
            )

        # Handle aliases
        if isinstance(value, str) and len(value) > 1 and value[0] == "&":
            # Store alias
            print(f"Saving value to aliases {value} -> {superset[key]}")
            aliases[value[1:]] = superset[key]
            continue
        if isinstance(value, str) and len(value) > 1 and value[0] == "*":
            # Load alias
            new_value = aliases.get(value[1:], None)
            print(f"Restoring value from aliases {value} -> {new_value}")
            value = new_value
        if isinstance(value, str) and len(value) > 1 and value[0] == "!":
            # Load alias & compare it does not match the current value
            old_value = aliases.get(value[1:], None)
            if old_value == superset[key]:
                return (False, f"{old_value} is equal to {superset[key]}")
            continue

        # Recursively assert nested dictionaries
        if isinstance(value, dict):
            is_sub, reason = __is_subset(superset[key], value, aliases)
            if not is_sub:
                return (
                    False,
                    f"nested dictionary {value} is not a subset"
                    f" of {superset[key]}: {reason}",
                )
        # Allow substring matching
        elif isinstance(value, str):
            if value not in superset[key]:
                return (False, f"{value} is not contained in {superset[key]}")
        # Default to equality comparison
        else:
            if not value == superset[key]:
                return (False, f"{value} is not equal to {superset[key]}")
    return (True, None)
