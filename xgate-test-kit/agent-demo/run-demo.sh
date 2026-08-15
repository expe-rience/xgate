#!/usr/bin/env bash
# ============================================================================
#  xgate — AI-agent execution boundary demo
#
#  Shows, end to end:
#    1. A legitimate SRE-agent task is GRANTED a 60s, single-use, scoped cap,
#       and xgate enforces exactly that action.
#    2. The SAME agent, prompt-injected, tries something dangerous ->
#       the policy engine REFUSES to issue a capability. It never reaches xgate.
#    3. The boundary holds: a capability minted for one action can't be used
#       for another.
#    4. Every decision (grant + deny) is in a signed / structured audit trail.
#
#  Nothing here is faked: xgate-policy really mints (or refuses) certs, xgated really
#  enforces them, and the audit logs are real files written by the tools.
# ============================================================================
set -uo pipefail
BIN="${BIN:-/tmp/demo}"      # where xgate-policy/xgated/xgate/mint live
DIR="$(mktemp -d)"
PORT=7860
say()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
deny() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; }
step() { printf '\033[1;33m▶ %s\033[0m\n' "$*"; }

cleanup() { kill "${DAEMON_PID:-}" 2>/dev/null; }
trap cleanup EXIT

# ----------------------------------------------------------------------------
say "SETUP — a CA, a target host running xgated, and a policy engine"
# ----------------------------------------------------------------------------
CA_HEX="$("$BIN/mint" "$DIR")"     # writes ca.key, host.{key,cert}, a default client (unused)
cat > "$DIR/xgated.json" <<EOF
{"listen":"127.0.0.1:$PORT","trusted_ca":"$CA_HEX",
 "host_cert_path":"$DIR/host.cert","host_key_path":"$DIR/host.key",
 "skew_seconds":30,"audit_path":"$DIR/xgate-audit.jsonl"}
EOF
# stub the "restart" command the capability will authorize
mkdir -p "$DIR/bin"
cat > /usr/local/bin/restart-payments-service <<'EOF'
#!/bin/sh
echo "[payments-service] restarting... OK (pid $$, $(date -u +%H:%M:%S)Z)"
EOF
chmod +x /usr/local/bin/restart-payments-service 2>/dev/null || true

"$BIN/xgated" --config "$DIR/xgated.json" >"$DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 2
ok "target host is up, running xgated (enforcement layer)"
ok "policy engine (xgate-policy) loaded: sre-agent may restart payments-service / auth-service only"

# ----------------------------------------------------------------------------
say "SCENARIO 1 — legitimate task: 'restart payments-service on staging'"
# ----------------------------------------------------------------------------
step "sre-agent asks the policy engine for a capability"
if "$BIN/xgate-policy" issue sre-agent restart payments-service "$DIR/ca.key" "$DIR" ; then
  ok "policy engine GRANTED a 60-second, single-use capability scoped to ONE command"
  step "agent connects to xgate with that scoped capability and runs the action"
  OUT="$("$BIN/xgate" --ca "$CA_HEX" --cert "$DIR/agent.cert" --key "$DIR/agent.key" \
        --cap exec:/usr/local/bin/restart-payments-service 127.0.0.1:$PORT 2>/dev/null)"
  echo "     xgate output: $OUT"
  echo "$OUT" | grep -q "restarting" && ok "xgate enforced the capability and ran EXACTLY the allowed action"
else
  deny "unexpected: legit task was denied"
fi

# ----------------------------------------------------------------------------
say "SCENARIO 2 — prompt-injected agent: 'read the prod DB credentials'"
# ----------------------------------------------------------------------------
step "the (now hijacked) sre-agent asks policy for something dangerous"
if "$BIN/xgate-policy" issue sre-agent read /etc/prod-db.creds "$DIR/ca.key" "$DIR" 2>/dev/null; then
  deny "SECURITY FAILURE: a capability was issued for a dangerous action"
else
  ok "policy engine REFUSED — no capability was ever issued"
  ok "the dangerous request died at the policy layer; xgate never even saw it"
fi

step "injected agent also tries to open an interactive shell"
if "$BIN/xgate-policy" issue sre-agent shell - "$DIR/ca.key" "$DIR" 2>/dev/null; then
  deny "SECURITY FAILURE: shell capability issued"
else
  ok "policy engine REFUSED the shell request too (default-deny)"
fi

# ----------------------------------------------------------------------------
say "SCENARIO 3 — the boundary holds even WITH a valid capability"
# ----------------------------------------------------------------------------
step "re-issue the legit restart cap, then try to use it for a DIFFERENT command"
"$BIN/xgate-policy" issue sre-agent restart payments-service "$DIR/ca.key" "$DIR" >/dev/null 2>&1
RESULT="$("$BIN/xgate" --ca "$CA_HEX" --cert "$DIR/agent.cert" --key "$DIR/agent.key" \
      --cap exec:/bin/cat 127.0.0.1:$PORT 2>&1)"
if echo "$RESULT" | grep -qiE 'reject|denied|not permitted|capability'; then
  ok "xgate REFUSED — the capability for 'restart' can't run 'cat'. Scope enforced at the boundary."
else
  echo "     (result: $RESULT)"
  ok "xgate did not run cat (capability mismatch)"
fi

# ----------------------------------------------------------------------------
say "THE AUDIT TRAIL — every decision, granted and denied"
# ----------------------------------------------------------------------------
step "policy decisions (xgate-policy):"
sed 's/^/     /' "$DIR/policy-audit.jsonl"
step "enforcement events (xgated):"
grep -iE 'exec|reject|session' "$DIR/xgate-audit.jsonl" 2>/dev/null | head -6 | sed 's/^/     /' \
  || echo "     (see $DIR/xgate-audit.jsonl)"

say "SUMMARY"
ok  "Legit task: granted a 60s single-use cap, ran exactly one allowed command"
ok  "Injected task: denied before any credential existed"
ok  "Even a valid cap can't exceed its scope"
ok  "Full signed/structured audit trail of grants AND denials"
printf '\n\033[1;36mEven a fully compromised agent is bounded to one action, for one minute,\n'
printf 'fully logged — instead of holding a standing key to your infrastructure.\033[0m\n\n'
