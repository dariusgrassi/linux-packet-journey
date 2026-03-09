#!/usr/bin/env python3
"""
tracer.py — Packet Journey Tracer (BCC Python)

Traces a single UDP packet (dst port 9999) from NIC IRQ to userspace
recvfrom(), then the echo reply from sendto() back out through the NIC.

The kernel-side BPF C program handles all filtering and timing.
This Python driver loads it, attaches probes, and formats the output.

Requires: sudo, python3-bcc, Linux 6.x with BTF
"""

import sys
import signal
import ctypes as ct
from bcc import BPF

# ─────────────────────────────────────────────────────────────────────────────
# BPF program (runs in the kernel)
# ─────────────────────────────────────────────────────────────────────────────
BPF_PROGRAM = r"""
#include <linux/skbuff.h>

#define TARGET_PORT  9999
#define TARGET_IRQ   58
#define MAX_COMM     16
#define MAX_NAME     32

// ── Event type IDs ────────────────────────────────────────────────────────────

enum stage_t {
    // RX path
    STAGE_IRQ            = 1,
    STAGE_NAPI           = 2,
    STAGE_NETIF          = 3,
    STAGE_IP             = 4,
    STAGE_UDP_RCV        = 5,
    STAGE_SOCK_READABLE  = 6,
    STAGE_RECVFROM       = 7,
    // TX path
    STAGE_SENDTO_ENTER   = 8,
    STAGE_UDP_SEND       = 9,
    STAGE_IP_OUTPUT      = 10,
    STAGE_NET_DEV        = 11,
    STAGE_VP_NOTIFY      = 12,
    STAGE_SENDTO_EXIT    = 13,
};

// ── Event struct (sent from kernel to userspace via perf ring buffer) ─────────

struct event_t {
    u32  stage;
    u64  ts;            // bpf_ktime_get_ns() at point of capture
    u64  skb_addr;      // sk_buff pointer (shows zero-copy: same address each stage)
    u32  pkt_len;       // packet length
    u16  dport;         // UDP dest port (confirmed at STAGE_UDP_RCV)
    u32  pid;
    s64  ret;           // syscall return value
    u64  sk_addr;       // socket pointer (STAGE_SOCK_READABLE)
    char comm[MAX_COMM];
    char irq_name[MAX_NAME];
};

BPF_PERF_OUTPUT(events);

// ── Global scalar state ───────────────────────────────────────────────────────
//
// BPF_ARRAY with 1 element is the idiomatic BCC way to hold global scalars.

struct irq_snap_t {
    u64  ts;
    char name[MAX_NAME];
};

BPF_ARRAY(g_irq_snap,  struct irq_snap_t, 1);  // snapshot of last IRQ 58
BPF_ARRAY(g_rx_state,  u32, 1);                 // 0=waiting, 1=udp_rcv, 2=sock
BPF_ARRAY(g_tx_state,  u32, 1);                 // 0=waiting, 1=armed, 2=in_sendto
BPF_ARRAY(g_target_sk, u64, 1);                 // socket pointer for RX filter

// ── Per-skb timestamp maps ────────────────────────────────────────────────────
//
// Keyed by skb address. Lets us track multiple in-flight packets (e.g. SSH)
// without their timestamps clobbering each other. Only the confirmed packet
// (dport==9999) gets emitted.

BPF_HASH(skb_t_irq,   u64, u64);
BPF_HASH(skb_t_napi,  u64, u64);
BPF_HASH(skb_t_netif, u64, u64);
BPF_HASH(skb_t_ip,    u64, u64);
BPF_HASH(skb_len,     u64, u32);

// ── Helpers ───────────────────────────────────────────────────────────────────

static __always_inline int is_python3(void) {
    char comm[MAX_COMM];
    bpf_get_current_comm(comm, sizeof(comm));
    return comm[0]=='p' && comm[1]=='y' && comm[2]=='t' &&
           comm[3]=='h' && comm[4]=='o' && comm[5]=='n' && comm[6]=='3';
}


// ══════════════════════════════════════════════════════════════════════════════
// RX PATH
// ══════════════════════════════════════════════════════════════════════════════

// ── Stage 1: IRQ ──────────────────────────────────────────────────────────────
//
// virtio0-input.0 fires IRQ 58. Packet data is already in guest RAM.
// Snapshot the timestamp and IRQ name; we'll emit this event later from
// udp_rcv once we've confirmed this is our packet.

TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    if (args->irq != TARGET_IRQ) return 0;

    int key = 0;
    struct irq_snap_t snap = {};
    snap.ts = bpf_ktime_get_ns();
    // args->name is a __data_loc field; BCC does not auto-resolve it.
    // IRQ 58 = virtio0-input.0 on this system — hardcoded.
    __builtin_memcpy(snap.name, "virtio0-input.0", 16);
    g_irq_snap.update(&key, &snap);
    return 0;
}

// ── Stage 2: NAPI GRO receive ─────────────────────────────────────────────────
//
// virtio_net's NAPI poll drains the RX virtqueue. Snapshot per-skb so
// concurrent SSH packets don't overwrite our state.

TRACEPOINT_PROBE(net, napi_gro_receive_entry)
{
    int key = 0;
    struct irq_snap_t *snap = g_irq_snap.lookup(&key);
    if (!snap || snap->ts == 0) return 0;   // no IRQ 58 seen yet

    u64 addr = (u64)args->skbaddr;
    u64 ts   = bpf_ktime_get_ns();
    u32 len  = args->len;

    skb_t_irq.update(&addr, &snap->ts);
    skb_t_napi.update(&addr, &ts);
    skb_len.update(&addr, &len);
    return 0;
}

// ── Stage 3: netif_receive_skb ────────────────────────────────────────────────

TRACEPOINT_PROBE(net, netif_receive_skb)
{
    u64 addr = (u64)args->skbaddr;
    if (!skb_t_napi.lookup(&addr)) return 0;

    u64 ts = bpf_ktime_get_ns();
    skb_t_netif.update(&addr, &ts);
    return 0;
}

// ── Stage 4: IP layer ─────────────────────────────────────────────────────────
//
// ip_rcv is inlined in kernel 6.17; ip_rcv_core is the first probeable point.
// No cross-context map lookup in the filter (type mismatch bug) — record all
// and discard at udp_rcv if it's not our packet.

int kprobe__ip_rcv_core(struct pt_regs *ctx)
{
    u64 addr = (u64)PT_REGS_PARM1(ctx);
    u64 ts   = bpf_ktime_get_ns();
    skb_t_ip.update(&addr, &ts);
    return 0;
}

// ── Stage 5: UDP layer — packet identity confirmed ────────────────────────────
//
// skb->data points to the UDP header. Read dest port to confirm dport==9999.
// Once confirmed, emit all accumulated RX events (stages 1-5) in one shot.

int kprobe__udp_rcv(struct pt_regs *ctx)
{
    u64 addr = (u64)PT_REGS_PARM1(ctx);

    u64 *t_napi = skb_t_napi.lookup(&addr);
    if (!t_napi) return 0;

    // Read UDP dest port: skb->data points to UDP header; dest port at offset 2
    struct sk_buff *skb = (struct sk_buff *)addr;
    void *data_ptr;
    bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), &skb->data);
    u16 dport_be;
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), data_ptr + 2);
    u16 dport = ntohs(dport_be);

    if (dport != TARGET_PORT) {
        // Not our packet — clean up to avoid map bloat
        skb_t_irq.delete(&addr);
        skb_t_napi.delete(&addr);
        skb_t_netif.delete(&addr);
        skb_t_ip.delete(&addr);
        skb_len.delete(&addr);
        return 0;
    }

    // Confirmed. Retrieve all per-skb state.
    u64 *t_irq   = skb_t_irq.lookup(&addr);
    u64 *t_netif = skb_t_netif.lookup(&addr);
    u64 *t_ip    = skb_t_ip.lookup(&addr);
    u32 *len     = skb_len.lookup(&addr);
    int  key     = 0;
    struct irq_snap_t *snap = g_irq_snap.lookup(&key);

    if (!t_irq || !t_netif || !t_ip || !len || !snap) return 0;

    struct event_t e = {};
    e.skb_addr = addr;
    e.pkt_len  = *len;

    // Emit Stage 1: IRQ
    e.stage = STAGE_IRQ;
    e.ts    = *t_irq;
    __builtin_memcpy(e.irq_name, snap->name, MAX_NAME);
    events.perf_submit(ctx, &e, sizeof(e));

    // Emit Stage 2: NAPI
    e.stage = STAGE_NAPI;
    e.ts    = *t_napi;
    events.perf_submit(ctx, &e, sizeof(e));

    // Emit Stage 3: netif_receive_skb
    e.stage = STAGE_NETIF;
    e.ts    = *t_netif;
    events.perf_submit(ctx, &e, sizeof(e));

    // Emit Stage 4: IP
    e.stage = STAGE_IP;
    e.ts    = *t_ip;
    events.perf_submit(ctx, &e, sizeof(e));

    // Emit Stage 5: udp_rcv (current time, dport confirmed)
    e.stage = STAGE_UDP_RCV;
    e.ts    = bpf_ktime_get_ns();
    e.dport = dport;
    events.perf_submit(ctx, &e, sizeof(e));

    // Advance RX state machine
    u32 one = 1;
    g_rx_state.update(&key, &one);

    // Clean up per-skb maps
    skb_t_irq.delete(&addr);
    skb_t_napi.delete(&addr);
    skb_t_netif.delete(&addr);
    skb_t_ip.delete(&addr);
    skb_len.delete(&addr);
    return 0;
}

// ── Stage 6: Socket wakeup ────────────────────────────────────────────────────
//
// sock_def_readable fires from within the udp_rcv call chain.
// One-shot: advance state 1→2 immediately to ignore subsequent calls.

int kprobe__sock_def_readable(struct pt_regs *ctx)
{
    int key = 0;
    u32 *state = g_rx_state.lookup(&key);
    if (!state || *state != 1) return 0;

    u64 sk = (u64)PT_REGS_PARM1(ctx);
    g_target_sk.update(&key, &sk);

    struct event_t e = {};
    e.stage   = STAGE_SOCK_READABLE;
    e.ts      = bpf_ktime_get_ns();
    e.sk_addr = sk;
    events.perf_submit(ctx, &e, sizeof(e));

    u32 two = 2;
    g_rx_state.update(&key, &two);
    return 0;
}

// ── Stage 7: recvfrom() returns ───────────────────────────────────────────────
//
// Fires as recvfrom() returns to userspace. Data has been copied from the
// sk_buff into the caller's buffer — the only copy in the entire RX journey.

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom)
{
    int key = 0;
    u32 *state = g_rx_state.lookup(&key);
    if (!state || *state != 2) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage = STAGE_RECVFROM;
    e.ts    = bpf_ktime_get_ns();
    e.pid   = bpf_get_current_pid_tgid() >> 32;
    e.ret   = args->ret;
    bpf_get_current_comm(e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));

    // Reset RX state; arm TX path for the echo reply
    u32 zero = 0, one = 1;
    g_rx_state.update(&key, &zero);
    g_tx_state.update(&key, &one);
    return 0;
}


// ══════════════════════════════════════════════════════════════════════════════
// TX PATH  (echo reply from receiver.py back to the Mac)
// ══════════════════════════════════════════════════════════════════════════════

// ── TX Stage 1: sendto() enters kernel ───────────────────────────────────────
//
// The data copy from userspace into sk_buff happens during this syscall —
// the only copy in the entire TX journey, symmetric to the RX recvfrom copy.

TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
    int key = 0;
    u32 *tx_state = g_tx_state.lookup(&key);
    if (!tx_state || *tx_state != 1) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage   = STAGE_SENDTO_ENTER;
    e.ts      = bpf_ktime_get_ns();
    e.pid     = bpf_get_current_pid_tgid() >> 32;
    e.pkt_len = (u32)args->len;
    bpf_get_current_comm(e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));

    u32 two = 2;
    g_tx_state.update(&key, &two);
    return 0;
}

// ── TX Stage 2: UDP layer ─────────────────────────────────────────────────────
//
// udp_send_skb() builds the sk_buff, writes the UDP header, computes checksum.
// arg0 = struct sk_buff *, arg1 = struct flowi4 *, arg2 = struct inet_cork *

int kprobe__udp_send_skb(struct pt_regs *ctx)
{
    int key = 0;
    u32 *tx_state = g_tx_state.lookup(&key);
    if (!tx_state || *tx_state != 2) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage    = STAGE_UDP_SEND;
    e.ts       = bpf_ktime_get_ns();
    e.skb_addr = (u64)PT_REGS_PARM1(ctx);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ── TX Stage 3: IP output ─────────────────────────────────────────────────────
//
// ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
//   arg0=net, arg1=sk, arg2=skb
// Adds IP header, TTL, checksum; runs netfilter POST_ROUTING.

int kprobe__ip_output(struct pt_regs *ctx)
{
    int key = 0;
    u32 *tx_state = g_tx_state.lookup(&key);
    if (!tx_state || *tx_state != 2) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage    = STAGE_IP_OUTPUT;
    e.ts       = bpf_ktime_get_ns();
    e.skb_addr = (u64)PT_REGS_PARM3(ctx);  // arg2 = skb
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ── TX Stage 4: Driver handoff ────────────────────────────────────────────────
//
// sk_buff enters the qdisc; virtio_net driver takes over.

TRACEPOINT_PROBE(net, net_dev_start_xmit)
{
    int key = 0;
    u32 *tx_state = g_tx_state.lookup(&key);
    if (!tx_state || *tx_state != 2) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage    = STAGE_NET_DEV;
    e.ts       = bpf_ktime_get_ns();
    e.skb_addr = (u64)args->skbaddr;
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// ── TX Stage 5: MMIO doorbell ─────────────────────────────────────────────────
//
// vp_notify() writes to the virtio-pci notify register — an MMIO write.
// This is what wakes QEMU to consume the TX virtqueue.
// On real hardware, the equivalent is a write to the NIC's tail register.

int kprobe__vp_notify(struct pt_regs *ctx)
{
    int key = 0;
    u32 *tx_state = g_tx_state.lookup(&key);
    if (!tx_state || *tx_state != 2) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage = STAGE_VP_NOTIFY;
    e.ts    = bpf_ktime_get_ns();
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ── TX Stage 6: sendto() returns ─────────────────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_exit_sendto)
{
    int key = 0;
    u32 *tx_state = g_tx_state.lookup(&key);
    if (!tx_state || *tx_state != 2) return 0;
    if (!is_python3()) return 0;

    struct event_t e = {};
    e.stage = STAGE_SENDTO_EXIT;
    e.ts    = bpf_ktime_get_ns();
    e.pid   = bpf_get_current_pid_tgid() >> 32;
    e.ret   = args->ret;
    bpf_get_current_comm(e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));

    u32 zero = 0;
    g_tx_state.update(&key, &zero);
    return 0;
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Python driver
# ─────────────────────────────────────────────────────────────────────────────

DIVIDER = "─" * 66

STAGE_IRQ           = 1
STAGE_NAPI          = 2
STAGE_NETIF         = 3
STAGE_IP            = 4
STAGE_UDP_RCV       = 5
STAGE_SOCK_READABLE = 6
STAGE_RECVFROM      = 7
STAGE_SENDTO_ENTER  = 8
STAGE_UDP_SEND      = 9
STAGE_IP_OUTPUT     = 10
STAGE_NET_DEV       = 11
STAGE_VP_NOTIFY     = 12
STAGE_SENDTO_EXIT   = 13

b      = None
t0_rx  = None   # RX base timestamp (set when STAGE_IRQ event arrives)
t0_tx  = None   # TX base timestamp (set when STAGE_SENDTO_ENTER arrives)
done   = False


def ts(event_ts, t0):
    """Format a nanosecond timestamp as [+seconds.nanoseconds]."""
    dt = event_ts - t0
    return f"[+{dt // 10**9}.{dt % 10**9:09d}]"


def decode(b_arr):
    return bytes(b_arr).rstrip(b"\x00").decode("utf-8", errors="replace")


def handle_event(cpu, data, size):
    global t0_rx, t0_tx, done

    e = b["events"].event(data)

    if e.stage == STAGE_IRQ:
        t0_rx = e.ts
        irq_name = decode(e.irq_name)
        print(DIVIDER)
        print("RX PATH: MAC -> python3")
        print(DIVIDER)
        print()
        print(f"[+0.000000000] IRQ 58 fired ({irq_name})")
        print(f"               ↳ driver:  virtio_net  (drivers/net/virtio_net.c)")
        print(f"               ↳ context: hard IRQ — CPU interrupted, minimal work done here")
        print(f"               ↳ DMA already wrote packet into guest RAM before this fired")
        print(f"               ↳ virtio_net masks the IRQ and schedules a NAPI softirq poll")
        print()

    elif e.stage == STAGE_NAPI:
        print(f"{ts(e.ts, t0_rx)} NAPI poll: enp0s1  len={e.pkt_len}")
        print(f"               ↳ driver:  virtio_net  virtnet_poll()")
        print(f"               ↳ context: softirq — runs after hard IRQ returns, on same CPU")
        print(f"               ↳ drains RX virtqueue; reclaims descriptor; allocates sk_buff")
        print(f"               ↳ GRO (Generic Receive Offload) may coalesce frames; single packet passes through")
        print()

    elif e.stage == STAGE_NETIF:
        print(f"{ts(e.ts, t0_rx)} netif_receive_skb: skb=0x{e.skb_addr:x}  len={e.pkt_len}  dev=enp0s1")
        print(f"               ↳ subsystem: net/core  (net/core/dev.c)")
        print(f"               ↳ reads EtherType field; dispatches to registered L3 handler")
        print(f"               ↳ for IPv4 (EtherType 0x0800): calls ip_rcv via ptype_base table")
        print(f"               ↳ sk_buff passed by pointer — no data copy")
        print()

    elif e.stage == STAGE_IP:
        print(f"{ts(e.ts, t0_rx)} ip_rcv_core: skb=0x{e.skb_addr:x}  len={e.pkt_len}")
        print(f"               ↳ subsystem: net/ipv4  (net/ipv4/ip_input.c)")
        print(f"               ↳ validates IP header: checksum, version, length, TTL")
        print(f"               ↳ netfilter NF_INET_PRE_ROUTING hook runs here (iptables INPUT chain)")
        print(f"               ↳ ip_local_deliver() strips IP header; dispatches on proto field (17=UDP)")
        print()

    elif e.stage == STAGE_UDP_RCV:
        print(f"{ts(e.ts, t0_rx)} udp_rcv: skb=0x{e.skb_addr:x}  dport={e.dport}")
        print(f"               ↳ subsystem: net/ipv4  (net/ipv4/udp.c)")
        print(f"               ↳ socket lookup: 4-tuple (src_ip, src_port, dst_ip, dst_port) in UDP hash table")
        print(f"               ↳ validates UDP checksum; calls udp_queue_rcv_skb()")
        print(f"               ↳ sk_buff appended to socket's receive queue (sk->sk_receive_queue)")
        print()

    elif e.stage == STAGE_SOCK_READABLE:
        print(f"{ts(e.ts, t0_rx)} sock_def_readable: sk=0x{e.sk_addr:x}")
        print(f"               ↳ subsystem: net/core  (net/core/sock.c)")
        print(f"               ↳ called from udp_queue_rcv_skb() after sk_buff is enqueued")
        print(f"               ↳ calls wake_up_interruptible() on sk->sk_wq wait queue")
        print(f"               ↳ moves receiver process from wait queue -> CPU run queue")
        print()

    elif e.stage == STAGE_RECVFROM:
        dt_ns = e.ts - t0_rx
        us    = dt_ns / 1_000
        comm  = decode(e.comm)
        print(f"{ts(e.ts, t0_rx)} recvfrom() returned: pid={e.pid} comm={comm}  bytes={e.ret}")
        print(f"               ↳ subsystem: net/ipv4  (net/ipv4/udp.c: __udp4_lib_recvmsg)")
        print(f"               ↳ skb_copy_datagram_iter() copies sk_buff data -> userspace buffer")
        print(f"               ↳ THIS IS THE ONLY COPY in the entire RX journey")
        print(f"               ↳ every earlier stage passed the same sk_buff by pointer")
        print(f"               ↳ Total RX kernel journey: {us/1000:.3f} µs")
        print(DIVIDER)
        print()

    elif e.stage == STAGE_SENDTO_ENTER:
        t0_tx = e.ts
        comm  = decode(e.comm)
        print(DIVIDER)
        print("TX PATH: python3 -> MAC (echo reply)")
        print(DIVIDER)
        print()
        print(f"[+0.000000000] sendto() entered: pid={e.pid} comm={comm}  bytes={e.pkt_len}")
        print(f"               ↳ subsystem: net/ipv4  (net/ipv4/udp.c: udp_sendmsg)")
        print(f"               ↳ context: process context — no IRQ or softirq involved")
        print(f"               ↳ skb_copy_from_iter() copies user buffer -> sk_buff (THE ONLY COPY on TX)")
        print()

    elif e.stage == STAGE_UDP_SEND:
        print(f"{ts(e.ts, t0_tx)} udp_send_skb: skb=0x{e.skb_addr:x}")
        print(f"               ↳ subsystem: net/ipv4  (net/ipv4/udp.c)")
        print(f"               ↳ UDP header written; checksum computed")
        print(f"               ↳ hands off to ip_send_skb() -> ip_local_out()")
        print()

    elif e.stage == STAGE_IP_OUTPUT:
        print(f"{ts(e.ts, t0_tx)} ip_output: skb=0x{e.skb_addr:x}")
        print(f"               ↳ subsystem: net/ipv4  (net/ipv4/ip_output.c)")
        print(f"               ↳ IP header added; TTL set; checksum computed")
        print(f"               ↳ netfilter NF_INET_POST_ROUTING hook runs here")
        print(f"               ↳ ARP lookup for next-hop MAC; sk_buff forwarded to net/core")
        print()

    elif e.stage == STAGE_NET_DEV:
        print(f"{ts(e.ts, t0_tx)} net_dev_start_xmit: dev=enp0s1  skb=0x{e.skb_addr:x}")
        print(f"               ↳ subsystem: net/core  (net/core/dev.c)")
        print(f"               ↳ sk_buff passed through qdisc (traffic control queue)")
        print(f"               ↳ dequeued immediately (no congestion); virtio_net driver takes over")
        print()

    elif e.stage == STAGE_VP_NOTIFY:
        print(f"{ts(e.ts, t0_tx)} vp_notify: virtio-pci notify register  ← MMIO WRITE")
        print(f"               ↳ driver:  virtio_net  (drivers/net/virtio_net.c)")
        print(f"               ↳ sk_buff descriptor added to TX virtqueue (shared memory ring)")
        print(f"               ↳ vp_notify() writes to virtio-pci notify register — this IS MMIO")
        print(f"               ↳ QEMU wakes up, reads TX descriptor, puts packet on host network")
        print(f"               ↳ on real hardware: equivalent write to NIC tail register via MMIO")
        print()

    elif e.stage == STAGE_SENDTO_EXIT:
        dt_ns = e.ts - t0_tx
        us    = dt_ns / 1_000
        comm  = decode(e.comm)
        print(f"{ts(e.ts, t0_tx)} sendto() returned: pid={e.pid} comm={comm}  bytes={e.ret}")
        print(f"               ↳ TX complete from kernel's perspective")
        print(f"               ↳ packet is now in QEMU's transmit queue")
        print(f"               ↳ Total TX kernel journey: {us/1000:.3f} µs")
        print(DIVIDER)
        print()
        print_comparison()
        done = True

    sys.stdout.flush()


def print_comparison():
    print("RX vs TX — two directions, two control paths")
    print()
    print("  Direction  Start             Copy          MMIO / IRQ      End")
    print("  ─────────  ────────────────  ────────────  ──────────────  ─────────────────")
    print("  RX         IRQ (hardware)    last step     IRQ at start    recvfrom() return")
    print("  TX         sendto() entry    first step    MMIO at end     sendto() return")
    print()
    print("  RX  hardware → softirq → net/core → net/ipv4 → socket queue → recvfrom()")
    print("        copy is LAST:  sk_buff → user buffer at syscall boundary")
    print("        MMIO: absent (virtio RX uses shared-memory virtqueue, no register write needed)")
    print()
    print("  TX  sendto() → net/ipv4 → net/core → virtio_net → MMIO doorbell → wire")
    print("        copy is FIRST: user buffer → sk_buff at sendto() entry")
    print("        MMIO: present — vp_notify() writes virtio-pci notify register to wake QEMU")
    print(DIVIDER)


def print_header():
    print("=== Packet Journey Tracer (BCC Python) ===")
    print("Waiting for a UDP packet to port 9999 on enp0s1...")
    print()
    print("Concepts:")
    print("  IRQ        Hardware interrupt — NIC signals CPU that work is ready")
    print("  softirq    Deferred software interrupt — NAPI poll runs here, not in IRQ context")
    print("  DMA        NIC writes packet directly to host RAM before IRQ fires")
    print("  virtio     Shared descriptor ring between guest driver and QEMU host")
    print("  NAPI       One IRQ triggers a poll loop -- not one IRQ per packet")
    print("  sk_buff    Kernel socket buffer; passed by pointer (zero-copy in kernel)")
    print("  zero-copy  Data not copied between kernel layers; only at the syscall boundary")
    print("  netfilter  Hook framework in net/core; runs at IP ingress/egress for iptables etc.")
    print()
    print("Note: what happens BEFORE stage 1 (inside the NIC) is not observable here.")
    print("      On this VM: QEMU copies the packet into guest RAM, then signals IRQ 58.")
    print("      On real hardware: the NIC DMA-writes to a pre-mapped ring buffer, then asserts IRQ.")
    print("      Either way, stage 1 (IRQ) is the earliest moment software can observe.")
    print()
    sys.stdout.flush()


def main():
    global b, done

    print_header()

    b = BPF(text=BPF_PROGRAM)
    b["events"].open_perf_buffer(handle_event)

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    while not done:
        b.perf_buffer_poll(timeout=100)

    sys.exit(0)


if __name__ == "__main__":
    main()
