# OVS collector

The `ovs` collector provides insights into the [OpenvSwitch](http://www.openvswitch.org/) datapath.

## Introduction: How OVS works

Before looking at the details of this collector, let's introduce how OVS kernel datapath works
(DPDK datapath is not yet supported).

OVS kernel datapath has two components: the kernel module and the userspace daemon
(a.k.a `ovs-vswitchd`). The userspace daemon is configured by the SDN controller
(e.g. [OVN](https://www.ovn.org)) using the OpenFlow® protocol, typically installing a large
number of rules distributed among several virtual bridges and tables.

On the other hand, in the linux kernel, the `openvswitch` module contains a flow table that can
store datapath flows (not to be confused with OpenFlow rules). This table is initially empty.

When port is attached to the openvswitch datapath and a packet arrives at it, the kernel module
will look up if a matching flow exists in the flow table. If it doesn't, the packet is sent to
the ovs-vswitchd daemon who will look up in the OpenFlow tables and decide what to do with it.
This process is called an **upcall**. Once ovs-vswitchd has determined what the right actions
to apply to the packet are, it will send them back to the kernel and instruct it to execute them
(this is called an "exec" operation). In addition, a datapath flow will be installed in the
kernel datapath (through a flow "put" operation) so that the next time a similar packet is received,
the kernel can handle it by itself, much faster.

So, it essentially works similar to a flow cache. For more details, visit the
[OVS documentation](https://docs.openvswitch.org/en/latest/).

## Probes and Events

The following diagram represents the OVS components as described in the previous section.



```none
                                ┌───────────────────────────────────────────────────────────────┐
                                │        ovs-vswitchd                                           │
                                │                   ┌────────────────────────┐                  │
                                │        ┌─────────►│OpenFlow classification ├───────┐          │
                                │        │          └───────────────┬────────┘       │          │
                                │        │                          │                │          │
                                │        │                          ▼                ▼          │
                                │        │                                                      │
                                │     upcall_recv                flow_put        flow_exec      │
                                └────────────────────────────────────────────────────┬──────────┘
                                    ▲   ▲                                            │
    userspace                       │   │                                            │
   ─────────────────────────────────┬───┬────────────────────────────────────────────┼────────────
    kernel                          │   │                                            │
             ┌──────────────────────┴───┴────────────────────────────────────────────┼──────────────┐
             │                upcall_enqueue          openvswitch module             │              │
             │                      ▲   ▲                                           action_execute  │
             │       upcall         │   │                                            │              │
slow path  ──┼──────────────────────┴───┘                                            └──────────────┤►
             │                                                                                      │
fast path  ──┼──────────────────────────────────────────────────────────────────────────────────────┼─►
             │                                 flow_lookup                           action_execute │
             │                                                                                      │
             └──────────────────────────────────────────────────────────────────────────────────────┘

```

The `slow path` represents the path a packet takes through OVS when a matching flow is not
found in the kernel datapath.
The `fast path` represents the path a packet takes through OVS when a matching flow is
found in the kernel datapath.

The following event types are emitted by the retis collector:

- **upcall**: It indicates a packet cannot be processed in the kernel (fast path) and
has to be sent to userspace.
- **upcall_enqueue**: It indicates a packet fragment being enqueued in the netlink socket
used to send packets to userspace. Note that if the packet is large enough, one *upcall*
event might be followed by multiple *upcall_enqueue* events.
- **upcall_recv**: USDT probe that is triggered when ovs-vswitchd receives the a packet.
- **flow_operation**: Represents a command operation executed by ovs-vswitchd. Two subtypes exist:
	- **flow_put**: USDT probe that indicates ovs-vswitchd will install a flow as a consequence
of the processing of the packet.
	- **flow_exec**: USDT probe that indicates ovs-vswitchd will instruct the kernel to execute
some actions on the packet.
- **flow_tbl_lookup**: Kernel kretprobe that contains the result of a flow lookup (hit or miss),
including the UFID(Unique Flow ID) of the matched flow, the number of masks hit, the number of
cache lookups as well as the flow and action pointers.
- **action_execute**: Kernel tracepoint that denotes that the kernel module is executing an
[OVS action](#OVS Actions) on a packet.


### OVS Actions

Events generated by the OVS collector can contain information of the OVS action that is being executed
on a packet. These actions are defined in
[openvswitch's uapi header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/openvswitch.h).

## OVS Tracking
For retis to be able to generate the above events, it has to have access to the ovs-vswitchd process
(i.e: it has to be on the same pid namespace), and the daemon must have been compiled with
[USDT support](https://docs.openvswitch.org/en/latest/topics/usdt-probes/). Since that might not
always be the case, USDT events have to be explicitly enabled using the `--ovs-track` flag.

Besides collecting USDT events, the `--ovs-track` also enables packet tracking. Packet tracking through
OVS consists on inserting some identifiers in the events that allow retis to correlate the events to their
originating packet. This means that, even if the packet was sent to upstream (upcall) and inserted back,
retis is able to keep track of it and know which skb it belongs to.

## OVS Detrace
OVS runtime information can be queried using a json-rpc interface that is typically exposed through a
UNIX socket. There are lots of commands available (see ovs-vswitchd(8)), but some of them are specially
relevant for traffic debugging:

- **dpctl/get {ufid}** shows the datapath flow given a UFID (Unique Flow ID).
- **ofproto/detrace {ufid}** (since OVS 3.4) shows the OpenFlow flows that created a particular
datapath flow.

The `--ovs-enrich-flows` option enables querying the running OVS daemon for this information
and adding it to the event list as a new event section called `ovs-detrace`.
Then, `retis sort` will combine this event with the `flow_tbl_lookup` event to show extra information
of each flow hit.

Queries to OVS are throttled to 20 requests per second.

### Example
Let's see an example. Say we capture ICMP traffic going through OVS and store the events in a file
with the following command:
```none
$ retis -p generic collect -f "icmp" -c ovs --ovs-track -o /tmp/events.json
```

We use the `generic` command to also probe some common places in the networking stack.
Now we use retis' post-processing `sort` command to group together events that belong to the same
packet.

```none
$ retis sort /tmp/events.json
```

We would be able to visualize OVS's behavior perfectly. First we see the packet being processed by the IP
stack.
```none
202388856790511 [ping] 3215414 [tp] net:net_dev_queue #b81253ea5defffff977be5ec6f80 (skb 18446629157470561024) n 0
  if 178 (p1_r) 172.200.0.2 > 172.200.0.3 ttl 64 tos 0x0 id 22378 off 0 [DF] len 84 proto ICMP (1) type 8 code 0
  + 202388856802883 [ping] 3215414 [k] skb_scrub_packet #b81253ea5defffff977be5ec6f80 (skb 18446629157470561024) n 1
    if 178 (p1_r) 172.200.0.2 > 172.200.0.3 ttl 64 tos 0x0 id 22378 off 0 [DF] len 84 proto ICMP (1) type 8 code 0
  + 202388856809633 [ping] 3215414 [tp] net:netif_rx #b81253ea5defffff977be5ec6f80 (skb 18446629157470561024) n 2
    if 179 (p1_l) 172.200.0.2 > 172.200.0.3 ttl 64 tos 0x0 id 22378 off 0 [DF] len 84 proto ICMP (1) type 8 code 0
  + 202388856816981 [ping] 3215414 [tp] net:net_dev_xmit #b81253ea5defffff977be5ec6f80 (skb 18446629157470561024) n 3
    if 179 (p1_l) 172.200.0.2 > 172.200.0.3 ttl 64 tos 0x0 id 22378 off 0 [DF] len 84 proto ICMP (1) type 8 code 0
  + 202388856829981 [ping] 3215414 [tp] net:netif_receive_skb #b81253ea5defffff977be5ec6f80 (skb 18446629157470561024) n 4
    if 179 (p1_l) 172.200.0.2 > 172.200.0.3 ttl 64 tos 0x0 id 22378 off 0 [DF] len 84 proto ICMP (1) type 8 code 0
```
Then we see how the first packet hits the OVS kernel module and is upcalled. The *upcall* event is followed by an *upcall_enqueue* event:

```none
  + 202388857516033 [handler7] 3215286/3215259 [tp] openvswitch:ovs_dp_upcall #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 5
    if 181 (p2_l) rxif 181 172.200.0.3 > 172.200.0.2 ttl 64 tos 0x0 id 58112 off 0 len 84 proto ICMP (1) type 0 code 0
    upcall (miss) port 3644007146 cpu 7

  + 202388857543026 [handler7] 3215286/3215259 [kr] queue_userspace_packet #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 6
    if 181 (p2_l) rxif 181 172.200.0.3 > 172.200.0.2 ttl 64 tos 0x0 id 58112 off 0 len 84 proto ICMP (1) type 0 code 0
    upcall_enqueue (miss) (7/202388857516033) q 2809249329 ret 0
```

Noticed the string `q 2809249329` in the *upcall_enqueue* event? That's a unique id that retis has generated for this upcall.
It's called a "queue identifier".

After the *upcall_enqueue* event, USDT events are generated showing userspace processing of the packet:

```none
  + 202388857658575 [handler9] 3215302/3215259 [u] dpif_recv:recv_upcall (ovs-vswitchd) #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 8
    upcall_recv q 2809249329 pkt_size 98
  + 202388857762836 [handler9] 3215302/3215259 [u] dpif_netlink_operate__:op_flow_put (ovs-vswitchd) #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 9
    flow_put q 2809249329 ts 202388857658575 (0)
  + 202388857771230 [handler9] 3215302/3215259 [u] dpif_netlink_operate__:op_flow_execute (ovs-vswitchd) #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 10
    flow_exec q 2809249329 ts 202388857658575 (0)
```

Remember the unique id we saw in the *upcall_enqueue* event? Here it is again on each USDT event
that belongs to the same packet!

Then, the packet is re-injected into the kernel and we see an action is being executed on it:
```none
  + 202388857827572 [handler9] 3215302/3215259 [tp] openvswitch:ovs_do_execute_action #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 11
    if 181 (p2_l) 172.200.0.3 > 172.200.0.2 ttl 64 tos 0x0 id 58112 off 0 len 84 proto ICMP (1) type 0 code 0
    exec oport 2 q 2809249329
```
The upcall tracking information is present on the *action_execute* event as well.

Finally, we see more events as the packet leaves OVS and is further processed by the kernel stack:

```none
  + 202388857835660 [handler9] 3215302/3215259 [tp] net:net_dev_queue #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 12
    if 179 (p1_l) 172.200.0.3 > 172.200.0.2 ttl 64 tos 0x0 id 58112 off 0 len 84 proto ICMP (1) type 0 code 0
  + 202388857842985 [handler9] 3215302/3215259 [k] skb_scrub_packet #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 13
    if 179 (p1_l) 172.200.0.3 > 172.200.0.2 ttl 64 tos 0x0 id 58112 off 0 len 84 proto ICMP (1) type 0 code 0
  + 202388857850009 [handler9] 3215302/3215259 [tp] net:netif_rx #b81253f4ce4bffff977beedbe580 (skb 18446629158226620928) n 14
    if 178 (p1_r) 172.200.0.3 > 172.200.0.2 ttl 64 tos 0x0 id 58112 off 0 len 84 proto ICMP (1) type 0 code 0
```

Retis uses the upcall queue identifier (`q 2809249329`) to determine that when the packet is reinjected
into the kernel, it's not really a "new" packet, but the old one that took a detour through userspace.
That way, retis shows all of these events indented under their first one.

