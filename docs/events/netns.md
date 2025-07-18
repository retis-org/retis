# Network namespace event

```none
ns [{unique id}/]{inum}
```

- `unique id` is a unique number provided by the kernel to help identifying
  network namespaces. It is guaranteed not to be reused. It might not be
  available on older kernels.

- `inum` is the inode number associated with a namespace and is unique while the
  namespace is in use. It can be reused after a namespace is deleted and because
  of this can't be used to uniquely identify a namespace in a Retis event
  collection. However the inode number is a value exposed to users, e.g. while
  looking at `/proc/<pid>/ns/net` or `/run/netns` (when using `iproute2` for the
  latter).
