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

### Hardware / firmware layer

**IRQ (Interrupt Request)**
A hardware signal from a device to the CPU indicating that work is ready. The
CPU saves its current register state, masks further IRQs at the same priority,
and vectors to the registered handler via the interrupt descriptor table (IDT on
x86, GIC on ARM). The handler runs in *hard IRQ context* — preemption is
disabled, no sleeping allowed. On this VM, IRQ 58 is `virtio0-input.0` (the RX
queue for enp0s1). See `/proc/interrupts` for per-CPU counts; watch them change
with `watch -n1 'grep virtio /proc/interrupts'` while the demo runs.

**DMA (Direct Memory Access)**
A mechanism that lets a peripheral bus-master transfer data directly to or from
system RAM without involving the CPU. On real hardware, the NIC's DMA engine
reads (TX) or writes (RX) using a physical bus address programmed by the driver;
the CPU is not involved in moving any payload byte. The driver uses
`dma_map_single()` / `dma_map_page()` to obtain a DMA-safe physical address,
and must call `dma_unmap_*()` before software can safely read the buffer
(cache-coherency). The CPU's first awareness of a received packet is the IRQ
that fires *after* DMA is done. On this VM the physical mechanism is emulated:
QEMU copies into guest RAM and then asserts the IRQ.

**MMIO (Memory-Mapped I/O)**
Device control registers are placed in the CPU's physical address space. The
driver reads and writes them with ordinary load/store instructions using
`ioremap()`-mapped virtual addresses. Reads/writes are non-cacheable and have
acquire/release semantics enforced by memory barriers (`wmb()`, `readl()`).
On this VM the virtio-pci notify register is MMIO; it is the only device
register touched in either path. Run `cat /proc/iomem | grep virtio` to see the
guest physical ranges. MMIO appears only in the **TX path** (`vp_notify`) —
RX uses the shared virtqueue ring without any register write.

**virtio ring buffer (virtqueue)**
The virtio specification defines a shared-memory ABI between the guest driver
and the host device emulator (QEMU). Each virtqueue is a ring of descriptors
in guest RAM. Each descriptor contains a guest-physical address, length, and
flags. For RX, the guest driver pre-populates the ring with empty receive
buffers; the host fills them and writes a "used" entry to signal completion.
For TX the guest writes a descriptor chain pointing at the sk_buff data; QEMU
reads it after the doorbell write (`vp_notify`). Inspect current ring geometry
with `ethtool -g enp0s1`. The ring size is the maximum number of in-flight
descriptors (default 256 on this setup); it sets an upper bound on NIC-to-host
parallelism.

### Kernel networking subsystem

**softirq**
A deferred software interrupt. The ten softirq vectors (indexed by
`include/linux/interrupt.h`) are run after hard IRQ handlers return, or by
`ksoftirqd` kernel threads if the backlog is too high. NAPI polling runs under
`NET_RX_SOFTIRQ` (vector 3). Softirq context allows preemption but not sleeping.
You can observe softirq activity with `watch -n1 'cat /proc/softirqs | grep NET'`.

**NAPI (New API)**
A hybrid interrupt/polling scheme introduced in Linux 2.6 to reduce interrupt
overhead at high packet rates. The flow: NIC fires one IRQ → driver masks
further NIC IRQs and schedules a NAPI poll → softirq runs the poll callback in
a budget loop (default `net.core.netdev_budget = 300` packets per CPU per
round) → when the ring is drained the driver re-enables NIC IRQs. If a round
exhausts its budget without draining, the remainder is left for `ksoftirqd`.
This batching amortises the per-IRQ overhead across many packets and improves
cache locality (descriptor ring data stays warm across the poll loop).

**GRO (Generic Receive Offload)**
A software receive coalescing layer that merges a burst of small TCP/UDP segments
arriving in the same NAPI poll round into a single large sk_buff before handing
it up to the network stack. This reduces per-packet processing cost (fewer
`ip_rcv`, `tcp_rcv` calls) and improves throughput. For a single UDP packet
(as in this demo) GRO is a no-op and the sk_buff passes through unchanged.
The hook is `napi_gro_receive` → `dev_gro_receive` → `napi_gro_flush`.

**Protocol demux (`ptype_base`)**
`__netif_receive_skb` reads the EtherType from the Ethernet header and looks up
a handler in the `ptype_base` hash table (keyed on EtherType). IPv4 packets
(EtherType 0x0800) are dispatched to `ip_rcv`. The table is populated at boot
by each L3 module calling `dev_add_pack()`. No explicit `if/switch` — pure
table dispatch.

**sk_buff**
The kernel's universal packet container (`include/linux/skbuff.h`). A small
metadata struct (~240 bytes) holding pointers into a separately allocated data
buffer: `head` (start of allocation), `data` (start of current protocol payload),
`tail` (end of payload), `end` (end of allocation). As the packet ascends the RX
stack each layer calls `skb_pull()` to advance `data` past its header, exposing
the next protocol. On TX, `skb_push()` reserves space and writes headers. The
buffer itself is never moved; only `data` is adjusted. The TX trace confirms this:
the same sk_buff address appears at `udp_send_skb`, `ip_output`, and
`net_dev_start_xmit`.

**Socket receive queue (`sk_receive_queue`)**
Each socket has a `struct sk_buff_head` linked list protected by a spinlock.
`udp_queue_rcv_skb()` appends the sk_buff to this list. The sleeping process is
then woken (see *wait queue* below). When `recvfrom()` runs it dequeues the
sk_buff and calls `skb_copy_datagram_iter()` to copy the payload into userspace.
Queue depth is bounded by `SO_RCVBUF` (default ~208 KB); excess packets are
silently dropped and counted in `ss -s` "dropped" or `netstat -su`.

**Netfilter / iptables**
A framework of hooks embedded at fixed points in the network stack. The hooks
relevant to RX are `NF_INET_PRE_ROUTING` (called from `ip_rcv`) and
`NF_INET_LOCAL_IN` (called from `ip_local_deliver`). Each hook can ACCEPT,
DROP, or modify the packet. iptables rules install callbacks on these hooks.
Even with no rules configured, traversing the empty hook list has measurable
latency (nanoseconds per packet). The TX equivalents are `NF_INET_LOCAL_OUT`
and `NF_INET_POST_ROUTING`.

**qdisc (queuing discipline)**
A traffic-control layer between `net/core` and the driver. Every network device
has a qdisc; the default is `pfifo_fast` (three-band priority FIFO). On TX,
`dev_queue_xmit()` enqueues the sk_buff into the qdisc and immediately dequeues
it if the driver queue is not congested. Under load (transmit queue stopped),
the qdisc absorbs bursts and shapes output rate. Inspect with
`tc qdisc show dev enp0s1`.

### Process scheduling

**Wait queue (`sk_wq`)**
A kernel data structure that holds a list of tasks sleeping on some condition.
When `recvfrom()` finds the receive queue empty, it calls `sk_wait_data()`,
which adds the calling task to `sk->sk_wq` and calls `schedule()`, yielding the
CPU. When `sock_def_readable()` is called from within `udp_rcv`, it calls
`wake_up_interruptible_all()` on that same wait queue, moving the task back to
RUNNABLE. The scheduler picks it up on the next tick or when the current CPU
becomes idle.

**Context switch (hard IRQ → softirq → process)**
The RX path crosses three execution contexts. Hard IRQ: CPU is diverted from
whatever it ran, no preemption, minimal work. Softirq: runs after IRQ handler
returns (or by `ksoftirqd`), preemption off. Process: the receiver task
returns from `recvfrom()` in normal process context. Each boundary has a cost:
saving/restoring registers, cache pollution. NAPI exists partly to collapse many
packets into one hard-IRQ → one-softirq-burst, amortising the first two transitions.

### Observability

**eBPF / BCC**
Extended Berkeley Packet Filter. A restricted virtual machine in the Linux
kernel that can run user-supplied programs in response to kernel events (kprobes,
tracepoints, perf events, XDP). Programs are verified by the kernel's BPF
verifier before loading (no loops with unbounded iteration, bounded stack,
safe memory accesses only). BCC (BPF Compiler Collection) provides a Python
front-end that compiles C source to eBPF bytecode using LLVM at runtime.
`tracer.py` uses BCC; `tracer.bt` uses bpftrace (a higher-level eBPF frontend).

**kprobe**
A dynamic instrumentation mechanism that patches a `breakpoint` (or `int3` on
x86) instruction at the first byte of an arbitrary kernel function. When the
CPU executes the breakpoint it traps to the kprobe handler, which runs the
attached BPF program, then single-steps the original instruction. kprobes fire
on live kernel code without requiring recompilation. The risk: if the target
function is inlined (removed from the compiled binary), the probe silently
attaches to nothing. Use `sudo bpftrace -l 'kprobe:foo'` to verify presence.
`ip_rcv` is inlined in kernel 6.17; `ip_rcv_core` is used instead.

**tracepoint**
A stable, explicitly placed probe point compiled into the kernel at known
locations with a documented ABI (argument names and types do not change across
kernel versions for a given tracepoint). Cheaper than kprobes (no breakpoint
trap) and stable across kernel builds. List all with `sudo bpftrace -l
'tracepoint:*'`. The IRQ, NAPI, netif, and syscall probes in this demo all use
tracepoints.

**perf ring buffer**
A lock-free, per-CPU circular buffer in shared memory between kernel and
userspace, used to stream BPF-generated events out of the kernel. BCC's
`BPF_PERF_OUTPUT` maps and bpftrace's `printf()` both write to this buffer.
Events are timestamped with `bpf_ktime_get_ns()` (CLOCK_MONOTONIC, nanosecond
resolution). The ring is polled by `epoll` in the userspace driver.

### Zero-copy and kernel bypass

**Zero-copy (within kernel)**
Every stage in both RX and TX passes the same sk_buff by pointer. The only
payload copies are at the syscall boundaries: `skb_copy_datagram_iter()` at
`recvfrom()` (RX) and `skb_copy_from_iter()` at `sendto()` (TX). No packet
bytes are copied between `ip_rcv_core`, `udp_rcv`, `sock_def_readable`, and
`netif_receive_skb` — they all see the same data pointer.

**MSG_ZEROCOPY**
A socket option (`setsockopt(SO_ZEROCOPY)` + `sendmsg()` with `MSG_ZEROCOPY`)
that eliminates the TX copy at `sendto()`. Instead the kernel pins the
userspace pages and builds an sk_buff that points directly into them via
`get_user_pages()`. The application receives a completion notification via
`recvmsg()` on the error queue when the pages are safe to reuse. Only worth the
overhead for payloads above ~10 KB.

**XDP (eXpress Data Path)**
A BPF hook at the earliest possible RX point — inside the driver, before
sk_buff allocation. XDP programs can DROP, PASS, REDIRECT, or TX-reflect a
packet in tens of nanoseconds. Because sk_buff allocation is skipped for dropped
packets, XDP is used for high-rate DDoS mitigation and load balancing (Cloudflare,
Facebook). On this VM it would hook into `virtnet_poll` before `napi_gro_receive`.

**DPDK (Data Plane Development Kit)**
A userspace I/O framework that bypasses the kernel network stack entirely. The
NIC is unbound from its kernel driver and re-bound to a UIO or VFIO shim; a
DPDK poll-mode driver (PMD) runs entirely in userspace, polling the NIC ring
directly via MMIO and DMA mappings. Eliminates IRQ overhead, softirq, sk_buff,
and all kernel stack latency. Latency drops to ~1 µs; throughput scales to
hundreds of Mpps. Requires dedicating physical CPU cores to the polling loop.

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
