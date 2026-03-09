# Packet Journey Demo

Traces a UDP packet's round trip through the Linux kernel: from the moment it
arrives on a NIC all the way to a userspace `recvfrom()` call (RX), then the
echo reply back out through the driver and onto the wire (TX).

Each kernel stage is surfaced with nanosecond timestamps, driver/subsystem
annotations, and source file references. A comparison summary at the end
highlights the structural differences between the two directions.

## Environment

| | |
|---|---|
| VM | Ubuntu 24.04 (kernel 6.17), ARM64, UTM on Apple Silicon |
| NIC | `enp0s1` — virtio-net paravirtualized NIC (QEMU/UTM) |
| Host | macOS (Apple Silicon) at the other end of the UTM virtual network |

## Files

| File | Where it runs | Purpose |
|---|---|---|
| `sender.py` | Mac host | Sends a single UDP packet to `192.168.64.3:9999` |
| `receiver.py` | VM | Listens on UDP 9999; echoes the packet back to the sender |
| `tracer.py` | VM (as root) | BCC Python tracer; hooks 13 kernel stages across RX and TX |
| `run_demo.sh` | Mac host | Orchestrates everything end-to-end |

## Implementation

`tracer.py` is a [BCC Python](https://github.com/iovisor/bcc) program. It
embeds a BPF C program (the kernel-side instrumentation) as a string and
compiles it at runtime using LLVM. The Python driver loads the probes, reads
events from a perf ring buffer, and formats the output.

```
tracer.py
├── BPF_PROGRAM  (C)   — compiled into eBPF bytecode at startup
│   ├── 7 RX probes    — IRQ → NAPI → netif → IP → UDP → socket → recvfrom
│   └── 6 TX probes    — sendto → UDP → IP → net_dev → vp_notify → sendto exit
└── Python driver      — loads probes, formats + prints each event
```

## Quick start

```bash
chmod +x run_demo.sh
./run_demo.sh
```

`run_demo.sh` will:
1. Upload `receiver.py` and `tracer.py` to the VM via `scp`
2. Start `receiver.py` on the VM (blocking in `recvfrom`)
3. Start `tracer.py` on the VM with `sudo python3`; BCC compiles the eBPF program (~4s)
4. Run `sender.py` locally to fire the test packet
5. Wait for the tracer to capture the full RX + TX journey and exit
6. Print what the receiver got

**Requirements on the Mac:** Python 3 in `$PATH` (standard on macOS).
**Requirements on the VM:** `python3-bcc`, `python3` (pre-installed per setup).

---

## What the NIC observability boundary looks like

Before Stage 1 (the IRQ), there is a hardware boundary that cannot be observed
from inside the guest:

```
On this VM:
  QEMU (Mac host process)
  └── receives packet from Mac network interface
  └── copies it into guest RAM (virtio shared memory)
  └── writes a "used" descriptor to the RX virtqueue
  └── asserts IRQ 58                    ← Stage 1 starts here

On real hardware:
  NIC DMA engine
  └── writes packet directly to a pre-mapped RAM buffer (DMA)
  └── asserts IRQ                        ← Stage 1 starts here
```

In both cases, the IRQ is the **earliest moment software can observe**. The
packet data is already in RAM before the CPU sees anything.

---

## RX path — 7 stages

### Stage 1 — IRQ (hardware boundary)

```
tracepoint:irq:irq_handler_entry  [IRQ 58]
driver: virtio_net  (drivers/net/virtio_net.c)
context: hard IRQ
```

`virtio0-input.0` fires IRQ 58. The driver does minimal work here: it masks
the interrupt and schedules a NAPI softirq poll to run later. The packet is
already in RAM.

### Stage 2 — NAPI poll

```
tracepoint:net:napi_gro_receive_entry
driver: virtio_net  virtnet_poll()
context: softirq
```

The NAPI poll callback runs in softirq context (not in the IRQ handler). The
virtio_net driver drains the RX virtqueue, reclaims completed descriptors, and
allocates `sk_buff` structs. GRO (Generic Receive Offload) may coalesce small
frames; a single packet passes through unchanged.

**NAPI** = New API. One IRQ triggers a poll loop rather than one interrupt per
packet. At high rates this dramatically reduces interrupt overhead.
(`net.core.netdev_budget` controls the polling budget, default 300.)

### Stage 3 — Protocol demux

```
tracepoint:net:netif_receive_skb
subsystem: net/core  (net/core/dev.c)
```

The sk_buff enters `__netif_receive_skb`, which reads the EtherType field and
dispatches to the registered L3 handler via the `ptype_base` table —
`ip_rcv` for IPv4 (EtherType 0x0800). The sk_buff is passed **by pointer**;
no data is copied.

### Stage 4 — IP layer

```
kprobe:ip_rcv_core
subsystem: net/ipv4  (net/ipv4/ip_input.c)
```

`ip_rcv` is inlined in kernel 6.17; `ip_rcv_core` is the first probeable
point. It validates the IP header (checksum, version, length, TTL) and runs
the netfilter `NF_INET_PRE_ROUTING` hook (iptables INPUT chain). Then
`ip_local_deliver()` strips the IP header and dispatches to the transport
layer via `inet_protos`, keyed on protocol field 17 (UDP).

### Stage 5 — UDP layer

```
kprobe:udp_rcv
subsystem: net/ipv4  (net/ipv4/udp.c)
```

`udp_rcv()` performs a 4-tuple socket lookup `(src_ip, src_port, dst_ip,
dst_port)` in the UDP hash table, validates the UDP checksum, and calls
`udp_queue_rcv_skb()` to append the sk_buff to the socket's receive queue
(`sk->sk_receive_queue`). We read `skb->data + 2` here to confirm
`dport == 9999` and identify our packet.

### Stage 6 — Socket wakeup

```
kprobe:sock_def_readable
subsystem: net/core  (net/core/sock.c)
```

Called from within the `udp_rcv` call chain after the sk_buff is enqueued.
`sock_def_readable()` calls `wake_up_interruptible()` on the socket's wait
queue (`sk->sk_wq`), moving the process sleeping inside `recvfrom()` from
the wait queue back to the CPU run queue.

### Stage 7 — Syscall boundary (RX copy)

```
tracepoint:syscalls:sys_exit_recvfrom
subsystem: net/ipv4  (net/ipv4/udp.c: __udp4_lib_recvmsg)
```

We hook `sys_exit_recvfrom` (not `sys_enter`) because the process was already
blocked inside the syscall. `sys_exit` fires as the call returns to userspace,
at which point `skb_copy_datagram_iter()` has copied the packet data from the
sk_buff into the caller's userspace buffer.

**This is the only copy in the entire RX journey.** Every earlier stage passed
the same sk_buff by pointer.

---

## TX path — 6 stages

### TX Stage 1 — Syscall boundary (TX copy)

```
tracepoint:syscalls:sys_enter_sendto
subsystem: net/ipv4  (net/ipv4/udp.c: udp_sendmsg)
context: process context
```

`sendto()` enters the kernel. `skb_copy_from_iter()` copies the caller's
userspace buffer into a newly allocated sk_buff.

**This is the only copy in the entire TX journey** — symmetric to the RX copy
at `recvfrom`, but it happens at the *start* of the journey rather than the
end.

### TX Stage 2 — UDP layer

```
kprobe:udp_send_skb
subsystem: net/ipv4  (net/ipv4/udp.c)
```

`udp_send_skb()` writes the UDP header and computes the checksum. It then
calls `ip_send_skb()` to hand off to the IP layer.

### TX Stage 3 — IP layer

```
kprobe:ip_output
subsystem: net/ipv4  (net/ipv4/ip_output.c)
```

Adds the IP header, sets TTL, computes the IP checksum. Runs the netfilter
`NF_INET_POST_ROUTING` hook. Resolves the next-hop MAC via ARP and forwards
the sk_buff to `net/core`.

### TX Stage 4 — Driver handoff

```
tracepoint:net:net_dev_start_xmit
subsystem: net/core  (net/core/dev.c)
```

The sk_buff passes through the qdisc (traffic control queue) and is
immediately dequeued (no congestion). The virtio_net driver takes ownership.

### TX Stage 5 — MMIO doorbell

```
kprobe:vp_notify
driver: virtio_net  (drivers/net/virtio_net.c)
```

The sk_buff descriptor is added to the TX virtqueue (shared memory ring).
`vp_notify()` then writes to the **virtio-pci notify register** — this is an
**MMIO write**, the only one in either path.

QEMU sees the write, wakes up, reads the TX descriptor, and puts the packet
onto the host network.

On real hardware, the equivalent operation is a write to the NIC's TX tail
register via MMIO, which signals the NIC's DMA engine to read from the ring.

### TX Stage 6 — Syscall returns

```
tracepoint:syscalls:sys_exit_sendto
```

`sendto()` returns to userspace. From the kernel's perspective, TX is complete.
The packet is in QEMU's transmit queue and will be sent asynchronously.

---

## RX vs TX comparison

```
Direction  Start             Copy          MMIO / IRQ      End
─────────  ────────────────  ────────────  ──────────────  ─────────────────
RX         IRQ (hardware)    last step     IRQ at start    recvfrom() return
TX         sendto() entry    first step    MMIO at end     sendto() return
```

**RX:** `hardware → softirq → net/core → net/ipv4 → socket queue → recvfrom()`
- Copy is **last**: sk_buff → user buffer at the syscall boundary
- MMIO: **absent** — virtio RX uses shared-memory virtqueue; no register write needed
- Context shift: hard IRQ → softirq → process context (scheduler wakeup)

**TX:** `sendto() → net/ipv4 → net/core → virtio_net → MMIO doorbell → wire`
- Copy is **first**: user buffer → sk_buff at syscall entry
- MMIO: **present** — `vp_notify()` writes the virtio-pci notify register
- Context: entirely in process context — no IRQ or softirq involved

---

## Concept glossary

**IRQ (Interrupt Request)**
A hardware signal from a device to the CPU indicating that work is ready. The
CPU interrupts whatever it was doing, saves state, and runs the registered
interrupt handler. On this VM, IRQ 58 is `virtio0-input.0` (enp0s1's RX queue).

**softirq**
A deferred software interrupt. Hard IRQ handlers are kept short; they schedule
softirq work to run after the IRQ returns. NAPI polling runs in softirq context.

**DMA (Direct Memory Access)**
The NIC writes packet data directly to system RAM without CPU involvement. The
CPU's first awareness is the IRQ. On real hardware (e.g. Intel igb) the driver
pre-allocates a ring of DMA-mapped buffers and programs their addresses into
NIC registers via MMIO.

**MMIO (Memory-Mapped I/O)**
NIC control registers are mapped into the CPU's physical address space. The
driver communicates with the NIC by reading and writing these addresses. On this
VM, these are virtio-pci registers; see `/proc/iomem` for the ranges. MMIO only
appears in the **TX path** (`vp_notify`) — RX uses the shared virtqueue ring.

**virtio ring buffer**
The virtio-net driver maintains a shared-memory ring of descriptors between the
guest kernel and QEMU. Each descriptor points to a guest-RAM buffer. For RX,
the driver pre-fills the ring with empty buffers; QEMU places received packets
into them. Inspect ring sizes with `ethtool -g enp0s1`.

**NAPI**
New API. A hybrid interrupt/polling scheme. The NIC fires one IRQ; the driver
disables further IRQs and polls the ring in a softirq budget loop until empty,
then re-enables IRQs. Reduces interrupt overhead at high packet rates.

**sk_buff**
The kernel's universal packet container. A small metadata struct with pointers
(`head`, `data`, `tail`, `end`) into a contiguous buffer. Passed by pointer
through every kernel layer — no copies between stages. Headers are "consumed"
by advancing the `data` pointer (`skb_pull`). The TX trace shows the same
sk_buff address at udp_send_skb, ip_output, and net_dev_start_xmit.

**Zero-copy (within kernel)**
Every stage in both RX and TX passes the same sk_buff by pointer. The only
copies are at the syscall boundaries: `skb_copy_datagram_iter()` at
`recvfrom()` (RX) and `skb_copy_from_iter()` at `sendto()` (TX). Kernel bypass
(DPDK, XDP, `MSG_ZEROCOPY`) can eliminate even those.

---

## Filtering and noise suppression

SSH traffic shares `enp0s1` and produces its own IRQs, NAPI events, and
syscalls. The tracer avoids false positives by:

1. **Per-skb maps**: timestamps stored per `skb_addr` key from NAPI onward; concurrent packets don't overwrite each other
2. **Port confirmation**: `kprobe:udp_rcv` reads `skb->data + 2` to verify `dport == 9999` before emitting any events
3. **State machine**: RX state (0→1→2) gates `sock_def_readable` and `recvfrom`; TX state (0→1→2) is armed only after RX completes
4. **comm filter**: TX probes filter on `comm == "python3"` to exclude SSH

---

## Troubleshooting

**Tracer prints nothing after sending**
BCC's compile + attach window (default 5s in `run_demo.sh`) may not be enough.
Increase `sleep 5` in `run_demo.sh`, or run the tracer and sender manually in
two terminals.

**`kprobe:udp_rcv` not found**
On some kernel builds `udp_rcv` is inlined. Fall back to
`tracepoint:net:udp_probe` and read `args->dport` directly.

**BCC compile errors on newer kernels**
BCC 0.29 uses system kernel headers at compile time. Headers from kernel 6.17+
include symbols (`struct bpf_wq`, `BPF_LOAD_ACQ`) that BCC's clang frontend
doesn't recognise. The fix used here: avoid `#include <net/sock.h>` (which
chains through to `linux/bpf.h`) and use only `#include <linux/skbuff.h>`.
