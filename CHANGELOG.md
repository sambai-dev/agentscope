# Changelog

## 0.2.0

- Capture requested `openat` paths and flags from real kernel events, enabling
  `SECRET_ACCESS` detections outside the simulator.
- Decode IPv4 and IPv6 `connect` destinations and ports from userspace
  sockaddrs.
- Support exact IP, glob, and IPv4/IPv6 CIDR network policies.
- Capture executable filename, uid, and cgroup id on process execution.
- Write escaped JSON directly into fixed RingBuf reservations and reject
  oversized records instead of emitting malformed payloads.
- Preserve compatibility with v0.1 identity-only probe records.
- Ship `asg.bpf.o` alongside the Linux release binary.
- Update Aya userspace to 0.14 and aya-ebpf to 0.2.

## 0.1.0

- Initial eBPF, simulator, policy engine, API, and dashboard release.
