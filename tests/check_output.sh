#!/usr/bin/env bash
# Ferrite OS integration test: validates QEMU serial output.
# Usage: ./tests/check_output.sh [output_file]
# If output_file is omitted, runs make run and captures output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
OUTPUT="${1:-}"
TMPFILE="$(mktemp /tmp/ferrite_out.XXXXXX)"
trap 'rm -f "$TMPFILE"' EXIT

if [ -z "$OUTPUT" ]; then
    echo "Running QEMU (20 s timeout)..."
    cd "$ROOT"
    make run > "$TMPFILE" 2>&1 &
    MAKE_PID=$!
    sleep 20
    kill $MAKE_PID 2>/dev/null || true
    wait $MAKE_PID 2>/dev/null || true
    OUTPUT="$TMPFILE"
fi

FAIL=0
PASS=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

check() {
    local desc="$1" pattern="$2"
    if grep -qF "$pattern" "$OUTPUT" 2>/dev/null; then pass "$desc"; else fail "$desc -- expected: $pattern"; fi
}

check_re() {
    local desc="$1" pattern="$2"
    if grep -qE "$pattern" "$OUTPUT" 2>/dev/null; then pass "$desc"; else fail "$desc -- pattern: $pattern"; fi
}

no_match() {
    local desc="$1" pattern="$2"
    if grep -qF "$pattern" "$OUTPUT" 2>/dev/null; then fail "$desc -- found: $pattern"; else pass "$desc"; fi
}

echo "=== Ferrite OS Integration Test Suite ==="
echo ""

echo "--- Safety ---"
no_match "No kernel panic"          "KERNEL PANIC"
no_match "No assertion failure"     "panicked at"

echo ""
echo "--- Phase 2: Memory ---"
check    "Buddy allocator ready"    "[OK] Buddy allocator ready"
check    "Sv48 paging on"           "[OK] Sv48 paging on"

echo ""
echo "--- Phase 3: Capabilities ---"
check    "Root CNode installed"     "[OK] Root CNode, UntypedMemory, trap handler installed"
check    "Phase 3 regression"       "[OK] Phase 3 regression pass"
check    "Empty slot rejected"      "Empty slot"
check    "Bad cap_type rejected"    "Bad cap_type"
check    "Occupied slot rejected"   "Occupied slot"

echo ""
echo "--- Phase 4: Scheduler ---"
check_re "MLFQ both threads ran"    "MLFQ scheduler: both threads ran 3"

echo ""
echo "--- Phase 5: IPC ---"
check    "Endpoint created"         "[OK] Endpoint"
check    "Notification created"     "[OK] Notification"
check    "Signal->Wait badge"       "Signal(0xAB)"
check    "Notif accumulation"       "Notification accumulation"
check    "Call/Reply round-trip"    "[OK] Call/Reply round-trip"
check    "Phase 5 complete"         "[OK] Phase 5 complete."

echo ""
echo "--- Phase 6: Interrupts ---"
check    "IRQControl installed"     "[OK] IRQControl cap installed"
check    "IRQHandler minted"        "[OK] IRQHandler(irq=10) minted"
check    "External IRQ received"    "[OK] External IRQ 10 received"
check    "IRQ_ACK succeeded"        "[OK] IRQ_ACK re-enabled source"

echo ""
echo "--- Phase 7: Process Bootstrap ---"
check    "VSpace created"           "[OK] Init VSpace created"
check    "Init process output"      "[init] OK"
check    "Phase 7 complete"         "Phase 7 complete."

echo ""
echo "--- Phase 8: ELF Loader ---"
check    "ELF VSpace created"       "[OK] ELF VSpace created"
check    "ELF process output"       "[init] Hello from ELF process!"
check    "Phase 8 complete"         "Phase 8 complete."

echo ""
echo "--- Phase 9: Multi-process IPC ---"
check    "Client called"            "[cl] calling"
check    "Server received"          "[sv] recv msg=42"
check    "Server replied"           "[sv] replied"
check    "Client got reply"         "[cl] reply=84"
check    "Phase 9 complete"         "Phase 9 complete."

echo ""
echo "--- Phase 10: ReplyRecv Fastpath ---"
check    "Server msg 1"             "[sv] #1 msg=42"
check    "Server msg 3"             "[sv] #3 msg=42"
check    "Client reply 84"          "[cl] reply=84"
check    "Phase 10 complete"        "Phase 10 complete."

echo ""
echo "--- Phase 11: Shared Memory ---"
check    "Frame cap created"        "[OK] Frame cap @ PA"
check    "Writer wrote"             "[sv] wrote to shared frame"
check    "Reader got data"          "[cl] shared data: Phase 11"
check    "Phase 11 complete"        "Phase 11 complete."

echo ""
echo "--- Phase 12: Userspace Retype ---"
check    "ep_a created ep2"         "[A] created ep2 at slot 16"
check    "ep_b called ep2"          "[B] ep2 reply=200"
check    "Phase 12 complete"        "Phase 12 complete."

echo ""
echo "--- Phase 13: Per-process CSpaces ---"
check    "CSpace A retype OK"       "[A] retype: OK"
check    "CSpace B retype denied"   "[B] retype: DENIED"
check    "Isolation verified"       "[OK] Per-process CSpace isolation verified"
check    "Phase 13 complete"        "Phase 13 complete."

echo ""
echo "--- Phase 14: IPC Cap Transfer ---"
check    "ep_shared created"        "[OK] ep_shared @ PA"
check    "ep_private created"       "[OK] ep_private @ PA"
check    "Grantor sent"             "[grantor] sent ep_private"
check    "Grantee received"         "[grantee] received ep_private"
check    "Grantor replied"          "[grantor] received msg=77"
check    "Grantee got reply"        "[grantee] ep_private reply=154"
check    "Cap transfer verified"    "[OK] Cap transfer verified"
check    "Phase 14 complete"        "Phase 14 complete."

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then
    echo "STATUS: ALL TESTS PASSED"
    exit 0
else
    echo "STATUS: FAILED"
    exit 1
fi
