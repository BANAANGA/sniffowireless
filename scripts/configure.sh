#!/usr/bin/env bash
# Interactive helper: finds the Wi-Fi, Ethernet and Bluetooth adapters on this machine and writes them to .env.
# Usage (from the repository folder):  ./scripts/configure.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || cp .env.example .env

# Set KEY=VALUE in .env, replacing an existing (or commented-out) line, else appending.
set_key() {
  local key=$1 val=$2
  if grep -qE "^#? ?${key}=" .env; then
    sed -i -E "s|^#? ?${key}=.*|${key}=${val}|" .env
  else
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}

default_if=$(ip route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')
wifi=() wired=()
for path in /sys/class/net/*; do
  name=$(basename "$path")
  [ -e "$path/device" ] || continue                  # skip lo, docker0, bridges, veth, VPN ...
  if [ -e "$path/phy80211" ]; then wifi+=("$name"); else wired+=("$name"); fi
done
bt=()
for path in /sys/class/bluetooth/hci*; do
  name=$(basename "$path")
  [[ $name =~ ^hci[0-9]+$ ]] && bt+=("$name")   # skip per-connection entries like hci0:2048
done

describe() {
  local n=$1 extra=""
  [ "$n" = "$default_if" ] && extra=" <- this machine's own network connection"
  local drv; drv=$(basename "$(readlink -f "/sys/class/net/$n/device/driver" 2>/dev/null)" 2>/dev/null || true)
  local mac; mac=$(cat "/sys/class/net/$n/address" 2>/dev/null || true)
  printf '    %-16s %-17s driver=%s%s\n' "$n" "$mac" "${drv:-?}" "$extra"
}

ask() {  # ask "question" "default" -> echoes the answer
  local reply
  read -r -p "$1 [$2]: " reply || true
  echo "${reply:-$2}"
}

suggest() {  # all adapters except the one the host uses for its own network
  local out=() n
  for n in "$@"; do [ "$n" != "$default_if" ] && out+=("$n"); done
  (IFS=,; echo "${out[*]-}")
}

echo
echo "Wi-Fi adapters found:"
if [ ${#wifi[@]} -gt 0 ]; then for n in "${wifi[@]}"; do describe "$n"; done; else echo "    (none - plug in a USB Wi-Fi adapter)"; fi
echo "  Use a dedicated adapter: monitor mode disconnects it from any network."
wifi_val=$(ask "WIFI_INTERFACES (comma-separated, empty = no Wi-Fi)" "$(suggest "${wifi[@]+"${wifi[@]}"}")")

echo
echo "Wired (Ethernet) adapters found:"
if [ ${#wired[@]} -gt 0 ]; then for n in "${wired[@]}"; do describe "$n"; done; else echo "    (none)"; fi
echo "  Optional. Ideally a spare adapter connected to a switch mirror/SPAN port."
eth_val=$(ask "ETH_INTERFACES (comma-separated, empty = no Ethernet capture)" "$(suggest "${wired[@]+"${wired[@]}"}")")

echo
echo "Bluetooth adapters found:"
if [ ${#bt[@]} -gt 0 ]; then printf '    %s\n' "${bt[@]}"; else echo "    (none)"; fi
bt_val=$(ask "BT_DEVICES (comma-separated, empty = no Bluetooth)" "$(IFS=,; echo "${bt[*]-}")")

echo
tz_default=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)
tz_val=$(ask "Time zone (TZ)" "$tz_default")

set_key WIFI_INTERFACES "$wifi_val"
set_key ETH_INTERFACES "$eth_val"
set_key BT_DEVICES "$bt_val"
set_key TZ "$tz_val"

for n in ${wifi_val//,/ } ${eth_val//,/ }; do
  [ "$n" = "$default_if" ] && echo "WARNING: $n carries this machine's own network connection; capturing on it can cut you off."
done
echo
echo "Saved to $(pwd)/.env:"
grep -E "^(WIFI_INTERFACES|ETH_INTERFACES|BT_DEVICES|TZ)=" .env | sed 's/^/    /'
echo
echo "Start yolo with:  docker compose up -d --build"
