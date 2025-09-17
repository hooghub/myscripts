#!/usr/bin/env bash
# sysinfo.sh - nicer system info + hostname check + IP quality tests
# Run as: sudo bash sysinfo.sh
# Copyright: you can modify freely

set -uo pipefail
LANG=C
VERBOSE=0
PINGCOUNT=4
HTTP_TEST_URL="http://speedtest.tele2.net/1MB.zip" # small file for simple http speed check (will be downloaded ~1MB)

# ---------- colors ----------
RED="$(tput setaf 1 2>/dev/null || echo '')"
GREEN="$(tput setaf 2 2>/dev/null || echo '')"
YELLOW="$(tput setaf 3 2>/dev/null || echo '')"
BLUE="$(tput setaf 4 2>/dev/null || echo '')"
BOLD="$(tput bold 2>/dev/null || echo '')"
RESET="$(tput sgr0 2>/dev/null || echo '')"

info()  { printf "%b\n" "${BLUE}${BOLD}[INFO]${RESET} $*"; }
ok()    { printf "%b\n" "${GREEN}${BOLD}[OK]${RESET} $*"; }
warn()  { printf "%b\n" "${YELLOW}${BOLD}[WARN]${RESET} $*"; }
err()   { printf "%b\n" "${RED}${BOLD}[ERROR]${RESET} $*"; }

# ---------- helper ----------
has_cmd() { command -v "$1" >/dev/null 2>&1; }

section() {
  printf "\n%s\n" "${BOLD}==== $* ====${RESET}"
}

short_kv() { printf "%-22s : %s\n" "$1" "$2"; }

# ---------- system basics ----------
system_info() {
  section "System"
  short_kv "Hostname" "$(hostname -f 2>/dev/null || hostname)"
  short_kv "OS" "$(awk -F= '/^PRETTY_NAME/ {print $2}' /etc/os-release 2>/dev/null | tr -d \")"
  short_kv "Kernel" "$(uname -sr)"
  short_kv "Uptime" "$(awk '{print int($1/86400) "d " int($1%86400/3600) "h " int($1%3600/60) "m"}' /proc/uptime 2>/dev/null || uptime -p)"
  if has_cmd lsb_release; then
    short_kv "Distro" "$(lsb_release -ds)"
  fi
}

cpu_mem_disk() {
  section "CPU / Memory / Disk"
  if has_cmd lscpu; then
    awk -F: '/Model name:/{print "CPU: "$2; exit}' <(lscpu) | sed 's/^ //'
  else
    short_kv "CPU" "$(cat /proc/cpuinfo | awk -F: '/model name/ {print $2; exit}' | sed 's/^ //')"
  fi
  short_kv "CPU cores" "$(nproc --all 2>/dev/null || cat /proc/cpuinfo | grep -c '^processor')"
  short_kv "Mem (free/total)" "$(free -h | awk '/^Mem:/ {print $3\" used / \"$2\" total\" }')"
  short_kv "Swap (used/total)" "$(free -h | awk '/^Swap:/ {print $3\" used / \"$2\" total\" }')"
  echo
  df -h --total | awk 'NR==1{printf "%-22s : %s\n","Filesystem","Size Use% Mounted"} NR>1 && $1=="total"{printf "%-22s : %s\n","Disk Total",$2" "$5} NR>1 && $1!="total"{print}'
}

network_info() {
  section "Network Interfaces & Routes"
  if has_cmd ip; then
    ip -br addr show | while read -r line; do
      printf "%-22s : %s\n" "IFACE" "$line"
      break
    done
    echo "Interfaces (brief):"
    ip -br addr show
    echo
    echo "Routes:"
    ip route show
  else
    warn "ip command not found; trying ifconfig/route"
    if has_cmd ifconfig; then ifconfig -a; fi
    if has_cmd route; then route -n; fi
  fi
}

listening_services() {
  section "Listening Services (TCP/UDP)"
  if has_cmd ss; then
    ss -tulnp | sed 's/  */ /g'
  elif has_cmd netstat; then
    netstat -tulpen
  else
    warn "Neither ss nor netstat found."
  fi
}

# ---------- hostname checks ----------
hostname_check() {
  section "Hostname Checks"
  H_FULL="$(hostname -f 2>/dev/null || hostname)"
  H_SHORT="$(hostname -s 2>/dev/null || echo $H_FULL)"
  short_kv "Hostname (full)" "$H_FULL"
  short_kv "Hostname (short)" "$H_SHORT"

  # /etc/hosts entry
  if grep -q "$H_SHORT" /etc/hosts 2>/dev/null; then
    ok "/etc/hosts contains hostname"
  else
    warn "/etc/hosts does not contain hostname"
    grep -n '127.0.1.1\|127.0.0.1' /etc/hosts 2>/dev/null || true
  fi

  # DNS resolution
  if has_cmd getent; then
    RES="$(getent hosts "$H_FULL" | awk '{print $1, $2}' || true)"
    if [ -n "$RES" ]; then
      ok "DNS resolves hostname: $RES"
    else
      warn "DNS did NOT resolve hostname via getent"
    fi
  else
    warn "getent not present to check DNS resolution"
  fi
}

# ---------- public IP & ASN ----------
public_ip_info() {
  section "Public IP / ASN"
  if has_cmd curl; then
    RESP="$(curl -s --max-time 8 https://ipinfo.io/json || true)"
    if [ -n "$RESP" ]; then
      IP="$(echo "$RESP" | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      ASN="$(echo "$RESP" | sed -n 's/.*"org"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      CITY="$(echo "$RESP" | sed -n 's/.*"city"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      REGION="$(echo "$RESP" | sed -n 's/.*"region"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      COUNTRY="$(echo "$RESP" | sed -n 's/.*"country"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      short_kv "Public IP" "${IP:-N/A}"
      short_kv "ASN / Org" "${ASN:-N/A}"
      short_kv "Location" "${CITY:-}${CITY:+, }${REGION:-}${REGION:+, }${COUNTRY:-}"
    else
      warn "ipinfo did not return data"
    fi
  else
    warn "curl missing: cannot fetch public IP info (install curl)"
    if has_cmd dig; then
      curl -s https://ipinfo.io/ip || true
    fi
  fi
}

# ---------- IP quality tests ----------
do_ping() {
  target="$1"
  if ! has_cmd ping; then
    warn "ping not available; skipping ping test for $target"
    return
  fi
  echo -n "Ping $target ... "
  # ping output parse
  P=$(ping -c "$PINGCOUNT" -W 2 "$target" 2>&1)
  if [ $? -ne 0 ]; then
    printf "%b\n" "${RED}FAIL${RESET}"
    echo "$P"
    return
  fi
  # extract packet loss and avg
  loss=$(echo "$P" | awk -F',' '/packet loss/ {gsub(/ /,"");print $3}' | sed 's/packetloss//;s/%//')
  rtt_line=$(echo "$P" | awk -F'/' '/rtt/ {print $5" ms avg"}')
  printf "%b\n" "${GREEN}OK${RESET}"
  printf "  -> Loss: %s, Avg RTT: %s\n" "${loss:-N/A}%" "${rtt_line:-N/A}"
}

do_tcp_connect() {
  target="$1"
  port="$2"
  if has_cmd nc; then
    echo -n "TCP $target:$port connect ... "
    nc -z -w3 "$target" "$port" >/dev/null 2>&1
    if [ $? -eq 0 ]; then ok "port open"; else warn "closed/unreachable"; fi
  else
    echo -n "TCP $target:$port connect (no nc) ... "
    if timeout 3 bash -c ">/dev/tcp/$target/$port" 2>/dev/null; then ok "open"; else warn "closed/unreachable"; fi
  fi
}

http_speed_test() {
  if ! has_cmd curl; then
    warn "curl not installed; skipping HTTP speed check"
    return
  fi
  section "HTTP Speed Test (simple)"
  echo "Downloading ~1MB from $HTTP_TEST_URL (will be thrown away)..."
  t0=$(date +%s.%N)
  out=$(mktemp)
  curl -s --max-time 15 -o "$out" "$HTTP_TEST_URL" 2>/dev/null || true
  t1=$(date +%s.%N)
  if [ -s "$out" ]; then
    size=$(stat -c%s "$out" 2>/dev/null || wc -c <"$out")
    dt=$(awk "BEGIN{print $t1 - $t0}")
    speed=$(awk "BEGIN{printf \"%.2f\", ($size/1024/1024)/$dt}")
    ok "Downloaded $(printf \"%.0f\" "$size") bytes in ${dt}s (~${speed} MB/s)"
    rm -f "$out"
  else
    warn "HTTP download failed or timed out"
    rm -f "$out" 2>/dev/null || true
  fi
}

ip_quality_checks() {
  section "IP Quality Checks (ping/connect)"
  # targets - common public resolvers / well-known
  targets=(8.8.8.8 1.1.1.1 9.9.9.9 google.com cloudflare.com)
  for t in "${targets[@]}"; do
    if [[ "$t" =~ ^[0-9] ]]; then
      do_ping "$t"
      do_tcp_connect "$t" 53
    else
      do_ping "$t"
      do_tcp_connect "$t" 443
    fi
  done

  # trace route (if available)
  if has_cmd traceroute; then
    section "Traceroute to 8.8.8.8 (first 10 hops)"
    traceroute -m 10 8.8.8.8 || true
  else
    warn "traceroute not installed; skip"
  fi

  # HTTP speed quick test
  http_speed_test
}

# ---------- main ----------
main() {
  system_info
  cpu_mem_disk
  network_info
  listening_services
  hostname_check
  public_ip_info
  ip_quality_checks

  section "Tips"
  echo "- If some commands are missing, install packages like: curl, iproute2 (ip), iputils (ping), net-tools/ss."
  echo "- To persist routes/hostname, check your distro's network manager (NetworkManager, systemd-networkd, /etc/network/interfaces, /etc/netplan/)."
  echo "- If you plan to use this on Alpine (ash), run with bash or adapt small bits (process substitution used above)."
}

main "$@"
