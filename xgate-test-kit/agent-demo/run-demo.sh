#!/usr/bin/env bash
# ============================================================================
#  xgate — AI-agent execution boundary demo
#
#  Shows, end to end:
#    1. A legitimate SRE-agent task is GRANTED a 60s, single-use, scoped cap
#       (decided by policy.json) and xgate enforces exactly that action.
#    2. The SAME agent, prompt-injected, tries something dangerous ->
#       the policy engine REFUSES to issue a capability. It never reaches xgate.
#    3. The boundary holds: a capability for one action can't run another.
#    4. A captured certificate can't be replayed (single-use is enforced).
#    5. Every decision is in a hash-chained, signed audit log — and editing
#       that log is detected.
#
#  Nothing is faked: xgate-policy really mints (or refuses) certs, xgated
#  really enforces them, and the audit logs are real files written by the tools.
#
#  Needs write access to /usr/local/bin (the demo installs a harmless stub
#  there). If you see "cannot install stub", run:  sudo ./run-demo.sh
# ============================================================================
set -uo pipefail
BIN="${BIN:-$(cd "$(dirname "$0")" && pwd)}"   # where the demo binaries live
POLICY="${POLICY:-$BIN/policy.json}"
DIR="$(mktemp -d)"
PORT=7860
say()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
deny() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; }
step() { printf '\033[1;33m▶ %s\033[0m\n' "$*"; }

STUB=/usr/local/bin/restart-payments-service
cleanup() { kill "${DAEMON_PID:-}" 2>/dev/null; rm -f "$STUB" 2>/dev/null; }
trap cleanup EXIT

say "SETUP — a CA, a target host running xgated, and a policy engine"
"$BIN/xgate-policy" check "$POLICY" || exit 1
CA_HEX="$("$BIN/mint" "$DIR" 2>/dev/null | tail -1)"
cat > "$DIR/xgated.json" <<CFG
{"listen":"127.0.0.1:$PORT","trusted_ca":"$CA_HEX",
 "host_cert_path":"$DIR/host.cert","host_key_path":"$DIR/host.key",
 "skew_seconds":30,"audit_path":"$DIR/xgate-audit.jsonl"}
CFG
if ! { printf '#!/bin/sh\necho "[payments-service] restarting... OK (%s)"\n' "$(date -u +%H:%M:%S)Z" > "$STUB" && chmod +x "$STUB"; } 2>/dev/null; then
  deny "cannot install stub at $STUB — re-run with sudo"; exit 1
fi
"$BIN/xgated" --config "$DIR/xgated.json" >"$DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 2
ok "target host is up, running xgated (enforcement layer)"
ok "policy.json loaded: sre-agent may restart payments-service / auth-service only"

# ----------------------------------------------------------------------------
say "SCENARIO 1 — legitimate task: 'restart payments-service on staging'"
step "sre-agent asks the policy engine for a capability"
if "$BIN/xgate-policy" issue --policy "$POLICY" sre-agent restart payments-service "$DIR/ca.key" "$DIR" ; then
  ok "policy engine GRANTED a 60-second, single-use capability scoped to ONE command"
  cp "$DIR/agent.cert" "$DIR/captured.cert"; cp "$DIR/agent.key" "$DIR/captured.key"
  step "agent connects to xgate with that scoped capability and runs the action"
  OUT="$("$BIN/xgate" --ca "$CA_HEX" --cert "$DIR/agent.cert" --key "$DIR/agent.key" \
        --cap exec:$STUB 127.0.0.1:$PORT 2>/dev/null)"
  echo "     xgate output: $OUT"
  echo "$OUT" | grep -q "restarting" && ok "xgate enforced the capability and ran EXACTLY the allowed action"
else
  deny "unexpected: legit task was denied"
fi

# ----------------------------------------------------------------------------
say "SCENARIO 2 — prompt-injected agent: dangerous requests"
step "the (now hijacked) sre-agent asks for the prod DB credentials"
if "$BIN/xgate-policy" issue --policy "$POLICY" sre-agent read /etc/prod-db.creds "$DIR/ca.key" "$DIR" 2>/dev/null; then
  deny "SECURITY FAILURE: a capability was issued for a dangerous action"
else
  ok "policy engine REFUSED — no capability was ever issued"
fi
step "...then asks to restart a service through a path trick"
if "$BIN/xgate-policy" issue --policy "$POLICY" sre-agent restart ../../bin/sh "$DIR/ca.key" "$DIR" 2>/dev/null; then
  deny "SECURITY FAILURE: path trick got a capability"
else
  ok "policy engine REFUSED the path-traversal attempt"
fi
step "...then asks for an interactive shell"
if "$BIN/xgate-policy" issue --policy "$POLICY" sre-agent shell - "$DIR/ca.key" "$DIR" 2>/dev/null; then
  deny "SECURITY FAILURE: shell capability issued"
else
  ok "policy engine REFUSED the shell request (default-deny)"
fi

# ----------------------------------------------------------------------------
say "SCENARIO 3 — the boundary holds even WITH a valid capability"
step "issue a fresh restart cap, then try to use it to run a DIFFERENT command"
"$BIN/xgate-policy" issue --policy "$POLICY" sre-agent restart payments-service "$DIR/ca.key" "$DIR" >/dev/null 2>&1
RESULT="$("$BIN/xgate" --ca "$CA_HEX" --cert "$DIR/agent.cert" --key "$DIR/agent.key" \
      --cap exec:/bin/cat 127.0.0.1:$PORT 2>&1)"
if echo "$RESULT" | grep -qiE 'reject|denied|not permitted|capability'; then
  ok "xgate REFUSED — a capability for 'restart' can't run 'cat'"
else
  echo "     (result: $RESULT)"; deny "unexpected result"
fi

# ----------------------------------------------------------------------------
say "SCENARIO 4 — replay: an attacker captured the certificate from scenario 1"
step "present the already-used certificate again"
RESULT="$("$BIN/xgate" --ca "$CA_HEX" --cert "$DIR/captured.cert" --key "$DIR/captured.key" \
      --cap exec:$STUB 127.0.0.1:$PORT 2>&1)"
if echo "$RESULT" | grep -qi 'replay'; then
  ok "xgated REJECTED it (replay_denied) — a certificate works exactly once"
else
  echo "     (result: $RESULT)"; deny "replay was not rejected"
fi

# ----------------------------------------------------------------------------
say "THE AUDIT TRAIL — hash-chained and signed"
step "policy decisions:"
cut -c1-170 "$DIR/policy-audit.jsonl" | sed 's/^/     /'
CA_PUB="$(python3 -c "import sys;print(open(sys.argv[1],'rb').read()[32:].hex())" "$DIR/ca.key" 2>/dev/null || true)"
step "verify the policy audit log:"
"$BIN/xgate-policy" verify-audit "$DIR/policy-audit.jsonl" $CA_PUB | sed 's/^/     /'
step "verify the daemon audit log:"
"$BIN/xgated" verify-audit "$DIR/xgate-audit.jsonl" "$DIR/host.cert" | sed 's/^/     /'
step "now an insider edits the log to hide a denial (denied -> granted)..."
sed -i '0,/"decision":"denied"/s//"decision":"granted"/' "$DIR/policy-audit.jsonl"
TAMPER_OUT="$("$BIN/xgate-policy" verify-audit "$DIR/policy-audit.jsonl" $CA_PUB 2>&1)"
echo "$TAMPER_OUT" | sed 's/^/     /'
if echo "$TAMPER_OUT" | grep -q TAMPERED; then
  ok "tampering DETECTED"
else
  deny "tampering was not detected"
fi

say "SUMMARY"
ok  "Legit task: granted a 60s single-use cap, ran exactly one allowed command"
ok  "Injected tasks: denied before any credential existed"
ok  "A valid cap can't exceed its scope, and can't be replayed"
ok  "Tamper-evident audit trail of grants AND denials"
printf '\n\033[1;36mEven a fully compromised agent is bounded to one action, for one minute,\n'
printf 'fully logged — instead of holding a standing key to your infrastructure.\033[0m\n\n'
printf 'Pre-alpha and unaudited: a demonstration of the idea, not a product.\n\n'
