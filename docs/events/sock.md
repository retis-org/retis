# Socket event

```none
sock {inode} {type} {proto} state {state} [rst {reset_reason}]
```

- `inode` is the socket inode number (can be retrieved using `ss -e`).
- `type` is the socket type (e.g. `SOCK_STREAM`). See `enum sock_type` in Linux.
- `proto` is the socket protocol (e.g. `IP`). See `IPPROTO_*` definitions in
  Linux.
- `state` is the socket state (e.g. `ESTABLISHED`).
- `reset_reason` is the reason why a reset packet was sent to the other side of
  the connection. See `enum sk_rst_reason` in Linux.
