print(len(events))

e = events[0]
print(e)
print(e.raw())
print(e.show())

for ev in events:
    print(hex(ev['skb-tracking'].tracking_id()))

# List of unique events.
print(set(map(lambda x: hex(x['skb-tracking'].tracking_id()), events)))

e = events[0]
print(e['skb-tracking'].match(events[1]['skb-tracking']))
print(e['skb-tracking'].match(events[10]['skb-tracking']))

# Scapy example

from scapy.all import *

pkt = events[0].raw()['skb']['packet']['packet']
hexdump(pkt)

p = Ether(bytes(pkt))
p.show()
print(tcpdump(p))
print(tdecode(p))

# ---

# The following can be set in a file and called with:
# $ retis python --exec foo.py

t = events[0]['skb-tracking']
for e in events:
    if e['skb-tracking'].match(t):
        print(e.show())
