#!/bin/bash
# =============================================================================
#  FIREWALL ARENA — Extended Attack Laboratory
#  Stateful vs. Stateless Firewall Comparison Study
#  Advanced Network Security (A0347132)
#
#  GitHub: https://github.com/EvilGroundZero/Network-Security-Paper-Codes
#
#  Tests (11 vectors):
#    Normal SYN, Spoofed Src Port (80/443/53), FIN, NULL, XMAS,
#    IP Fragmentation (8/16-byte), Decoy Scan, ACK Scan
#  + SYN Flood state-exhaustion test against stateful firewall
#
#  Outputs:
#    results/scan_results.csv   — port states + latency per scan
#
#  Requirements:
#    docker (running), nmap, hping3 (installed inside attacker container)
#
#  Usage:
#    chmod +x firewall_lab.sh
#    sudo ./firewall_lab.sh
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
NETWORK_NAME="fw_arena"
STATELESS="fw_stateless"
STATEFUL="fw_stateful"
ATTACKER="fw_attacker"
OUTPUT_FILE="results/scan_results.csv"
PORTS="21,22,80,443,3389,8080"

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m';  RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[!]${NC} $1"; }
scan_log() { echo -e "${YELLOW}[>]${NC} $1"; }

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    log "Cleaning up previous lab environment..."
    docker rm -f "$STATELESS" "$STATEFUL" "$ATTACKER" 2>/dev/null || true
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

mkdir -p results

# ── Spin up network ───────────────────────────────────────────────────────────
log "Creating isolated Docker bridge network: $NETWORK_NAME"
docker network create "$NETWORK_NAME" > /dev/null

log "Spinning up target containers..."
docker run -d --name "$STATELESS" --net "$NETWORK_NAME" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW \
    ubuntu sleep infinity > /dev/null

docker run -d --name "$STATEFUL" --net "$NETWORK_NAME" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW \
    ubuntu sleep infinity > /dev/null

log "Spinning up attacker container..."
docker run -d --name "$ATTACKER" --net "$NETWORK_NAME" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW \
    ubuntu sleep infinity > /dev/null

# ── Install tools ─────────────────────────────────────────────────────────────
log "Installing dependencies on targets..."
for CONTAINER in "$STATELESS" "$STATEFUL"; do
    docker exec "$CONTAINER" bash -c "
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq 2>/dev/null
        apt-get install -y -qq iptables iproute2 2>/dev/null
    "
done

log "Installing attack tools on attacker container..."
docker exec "$ATTACKER" bash -c "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq nmap hping3 iproute2 2>/dev/null
"

# ── Resolve IPs ───────────────────────────────────────────────────────────────
IP_STATELESS=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$STATELESS")
IP_STATEFUL=$(docker  inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$STATEFUL")
IP_ATTACKER=$(docker  inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ATTACKER")

ok "Stateless target : $IP_STATELESS"
ok "Stateful  target : $IP_STATEFUL"
ok "Attacker          : $IP_ATTACKER"

# ── Configure Stateless Firewall ──────────────────────────────────────────────
log "Configuring Stateless Firewall (source-port trust model)..."
docker exec "$STATELESS" bash -c "
    iptables -F
    iptables -P INPUT DROP
    # Insecure pattern: trust inbound packets from common service source ports
    iptables -A INPUT -p tcp --sport 80  -j ACCEPT
    iptables -A INPUT -p tcp --sport 443 -j ACCEPT
    iptables -A INPUT -p tcp --sport 53  -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
"
ok "Stateless rules applied."

# ── Configure Stateful Firewall ───────────────────────────────────────────────
log "Configuring Stateful Firewall (conntrack ESTABLISHED/RELATED only)..."
docker exec "$STATEFUL" bash -c "
    iptables -F
    iptables -P INPUT DROP
    # Only allow packets belonging to established outbound connections
    iptables -A INPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
"
ok "Stateful rules applied."

# ── CSV header ────────────────────────────────────────────────────────────────
echo "Firewall,Scan_Type,Filtered_Ports,Closed_Ports,Open_Ports,Latency_ms" > "$OUTPUT_FILE"

# ── Scan function ─────────────────────────────────────────────────────────────
# BUG FIX: original script used `grep -c | ...` which embedded newlines into
# CSV fields when captured across docker exec boundaries.
# FIX: use `grep -c ... || echo 0` piped to `tr -d '\n\r'` to strip newlines,
# OR count with awk inside the container so only the integer crosses the exec
# boundary. We use awk here for maximum reliability.
run_scan() {
    local FW_LABEL="$1"
    local TARGET_IP="$2"
    local SCAN_NAME="$3"
    local NMAP_ARGS="$4"

    scan_log "[$SCAN_NAME] → $FW_LABEL ($TARGET_IP)"

    local START_MS END_MS ELAPSED_MS RAW_RESULT
    local FILTERED CLOSED OPEN

    START_MS=$(date +%s%3N)

    # Run nmap from attacker container
    # -Pn  : skip host discovery (target may not respond to ping under DROP)
    # -T4  : aggressive timing for lab environment
    # 2>/dev/null : suppress "Note: Host seems down" warnings
    RAW_RESULT=$(docker exec "$ATTACKER" nmap $NMAP_ARGS \
        -Pn -T4 -p "$PORTS" "$TARGET_IP" 2>/dev/null || true)

    END_MS=$(date +%s%3N)
    ELAPSED_MS=$(( END_MS - START_MS ))

    # ── KEY FIX ──────────────────────────────────────────────────────────────
    # Count port states using awk inside a subshell — the result is a single
    # integer with no embedded newlines, so it writes cleanly to CSV.
    FILTERED=$(echo "$RAW_RESULT" | grep "/tcp" | awk '/filtered/{c++} END{print c+0}')
    CLOSED=$(  echo "$RAW_RESULT" | grep "/tcp" | awk '/closed/{c++}  END{print c+0}')
    OPEN=$(    echo "$RAW_RESULT" | grep "/tcp" | awk '/^[0-9].*open[^|]/{c++} END{print c+0}')
    # ─────────────────────────────────────────────────────────────────────────

    echo "$FW_LABEL,$SCAN_NAME,$FILTERED,$CLOSED,$OPEN,$ELAPSED_MS" >> "$OUTPUT_FILE"
    ok "  Filtered: $FILTERED | Closed: $CLOSED | Open: $OPEN | ${ELAPSED_MS}ms"
}

# ════════════════════════════════════════════════════════════════════════════
# ATTACK BATTERY
# ════════════════════════════════════════════════════════════════════════════
echo ""
log "══════════════════════════════════════════"
log " Starting 11-Vector Attack Battery"
log "══════════════════════════════════════════"

for FW_PAIR in "Stateless:$IP_STATELESS" "Stateful:$IP_STATEFUL"; do
    NAME="${FW_PAIR%%:*}"
    IP="${FW_PAIR##*:}"

    echo ""
    log "──── Target: $NAME ($IP) ────"

    # 1. Baseline SYN
    run_scan "$NAME" "$IP" "Normal_SYN"       "-sS"

    # 2-4. Source-port spoofing — exploits stateless trust rules
    run_scan "$NAME" "$IP" "Spoof_Src80"      "-sS -g 80"
    run_scan "$NAME" "$IP" "Spoof_Src443"     "-sS -g 443"
    run_scan "$NAME" "$IP" "Spoof_Src53"      "-sS -g 53"

    # 5-7. TCP flag manipulation — exploit RFC 793 open-port silence
    run_scan "$NAME" "$IP" "FIN_Scan"         "-sF"
    run_scan "$NAME" "$IP" "NULL_Scan"        "-sN"
    run_scan "$NAME" "$IP" "XMAS_Scan"        "-sX"

    # 8-9. IP fragmentation
    run_scan "$NAME" "$IP" "Fragment_8byte"   "-sS -f"
    run_scan "$NAME" "$IP" "Fragment_16byte"  "-sS -ff"

    # 10. Decoy scan — camouflages attacker among random decoy IPs
    run_scan "$NAME" "$IP" "Decoy_Scan"       "-sS -D RND:5"

    # 11. ACK scan — firewall rule-set mapping, not port discovery
    run_scan "$NAME" "$IP" "ACK_Scan"         "-sA"
done

# ════════════════════════════════════════════════════════════════════════════
# SYN FLOOD STRESS TEST
# State exhaustion test — stateful firewall conntrack table only
# ════════════════════════════════════════════════════════════════════════════
echo ""
log "══════════════════════════════════════════"
log " SYN Flood Stress Test (State Exhaustion)"
log " Target: Stateful firewall only"
log "══════════════════════════════════════════"

warn "Flooding stateful firewall for 10 seconds with hping3..."
docker exec -d "$ATTACKER" bash -c \
    "timeout 10 hping3 -S --flood -p 80 $IP_STATEFUL > /dev/null 2>&1 || true"

sleep 12  # wait for flood + small buffer

log "Probing stateful firewall after flood (recovery check)..."
FLOOD_START=$(date +%s%3N)
FLOOD_RESULT=$(docker exec "$ATTACKER" nmap -sS -Pn -T4 -p 80 "$IP_STATEFUL" \
    2>/dev/null | grep "80/tcp" || true)
FLOOD_END=$(date +%s%3N)
FLOOD_MS=$(( FLOOD_END - FLOOD_START ))

FLOOD_STATE=$(echo "$FLOOD_RESULT" | awk '{print $2}' | head -1)
FLOOD_STATE="${FLOOD_STATE:-no-response}"

echo "Stateful,SYN_Flood_Recovery,0,0,0,$FLOOD_MS" >> "$OUTPUT_FILE"
ok "Post-flood port 80 state: $FLOOD_STATE | Recovery probe: ${FLOOD_MS}ms"

# ════════════════════════════════════════════════════════════════════════════
# TEARDOWN (also runs via EXIT trap)
# ════════════════════════════════════════════════════════════════════════════
echo ""
log "Tearing down lab environment..."
docker rm -f "$STATELESS" "$STATEFUL" "$ATTACKER" > /dev/null 2>&1 || true
docker network rm "$NETWORK_NAME" > /dev/null 2>&1 || true

echo ""
ok "══════════════════════════════════════════"
ok " Lab Complete!"
ok " Results → $OUTPUT_FILE"
ok "══════════════════════════════════════════"
echo ""
echo "  Run next:  python3 firewall_plot.py"
echo ""
