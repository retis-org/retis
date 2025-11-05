# Socket event

```none
sock {inode} {type} {proto}
```

- `inode` is the socket inode number (can be retrieved using `ss -e`).
- `type` is the socket type (e.g. `SOCK_STREAM`). See `enum sock_type` in Linux.
- `proto` is the socket protocol (e.g. `IP`). See `IPPROTO_*` definitions in
  Linux.
