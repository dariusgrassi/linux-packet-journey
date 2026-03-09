#!/usr/bin/env bash
#
# run_demo.sh — Orchestrates the packet journey demo.
#
# Runs on the Mac host. Uploads files to the VM, starts the receiver and
# tracer there, fires a single test packet from the Mac, then waits for
# the tracer to capture the full RX+TX journey before exiting.
#
# Usage: ./run_demo.sh

set -uo pipefail

VM="darius@192.168.64.3"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Kill the receiver on the VM when this script exits
cleanup() {
    ssh "$VM" "pkill -f 'python3 /tmp/receiver.py' 2>/dev/null || true" &>/dev/null || true
    ssh "$VM" "pkill -f 'python3 /tmp/tracer.py'   2>/dev/null || true" &>/dev/null || true
}
trap cleanup EXIT

echo "=== Packet Journey Demo ==="
echo ""

# 1. Upload files + kill any leftover processes from a previous run
echo "[1/4] Uploading files to VM..."
scp -q "$DIR/receiver.py" "$DIR/tracer.py" "$VM:/tmp/"
ssh "$VM" 'sudo pkill -f "python3 /tmp/tracer.py" 2>/dev/null; pkill -f "python3 /tmp/receiver.py" 2>/dev/null; true'

# 2. Start receiver first — it must be blocking in recvfrom() before the
#    packet arrives so that sock_def_readable and sys_exit_recvfrom fire.
echo "[2/4] Starting UDP receiver on VM (port 9999)..."
ssh "$VM" 'nohup python3 /tmp/receiver.py > /tmp/receiver.log 2>&1 < /dev/null &'
sleep 2
# Verify it actually started
if ! ssh "$VM" 'pgrep -f "python3 /tmp/receiver.py" > /dev/null'; then
    echo "ERROR: receiver.py did not start. Check /tmp/receiver.log on the VM."
    exit 1
fi

# 3. Start tracer — BCC compiles the eBPF program at startup (~3-4s).
#    Receiver is already blocked in recvfrom(); tracer just needs to attach.
echo "[3/4] Starting BCC tracer (compiling + attaching probes, ~4s)..."
echo ""
ssh "$VM" "sudo python3 /tmp/tracer.py" &
TRACER_PID=$!

# Give BCC time to compile and attach all probes.
sleep 5

# 4. Fire the test packet
echo "[4/4] Sending test packet from Mac -> 192.168.64.3:9999"
echo ""
python3 "$DIR/sender.py"
echo ""

# Wait for the tracer to capture the full RX+TX journey and exit
wait "$TRACER_PID"

# Show what the receiver actually got
echo ""
echo "--- Receiver log (VM) ---"
ssh "$VM" "cat /tmp/receiver.log"
