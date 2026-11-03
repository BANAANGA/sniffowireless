#!/usr/bin/env bash
# Interactive helper: finds the Wi-Fi, Ethernet and Bluetooth adapters on this machine and writes them to .env,
# then checks the Wi-Fi regulatory domain (country) that 6 GHz needs and offers to fix it.
# Usage (from the repository folder):  ./scripts/configure.sh              full setup
#                                      ./scripts/configure.sh --regdomain  only check / fix the country setting
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

yes_no() {  # yes_no "question" y|n -> success for yes
  local reply hint="y/N"
  [ "$2" = y ] && hint="Y/n"
  read -r -p "$1 [$hint]: " reply || true
  [[ ${reply:-$2} =~ ^[Yy] ]]
}
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
env_val() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }

install_pkgs() {  # install packages with the host's package manager
  if command -v apt-get >/dev/null; then as_root apt-get install -y "$@"
  elif command -v pacman >/dev/null; then as_root pacman -S --needed --noconfirm "$@"
  elif command -v dnf >/dev/null; then as_root dnf install -y "$@"
  elif command -v zypper >/dev/null; then as_root zypper --non-interactive install "$@"
  elif command -v apk >/dev/null; then as_root apk add "$@"
  else echo "    No supported package manager found: install $* yourself."; return 1
  fi
}

country_from_tz() {  # Europe/Amsterdam -> NL
  [ -f /usr/share/zoneinfo/zone.tab ] && awk -v tz="$1" '$3 == tz {print $1; exit}' /usr/share/zoneinfo/zone.tab || true
}
global_country() { iw reg get 2>/dev/null | awk '/^global/ {g = 1; next} g && /^country/ {sub(":", "", $2); print $2; exit}' || true; }
regdb_present() { compgen -G "/lib/firmware/regulatory.db*" >/dev/null || compgen -G "/usr/lib/firmware/regulatory.db*" >/dev/null; }
six_ghz() {  # six_ghz IFACE all|enabled -> number of 6 GHz channels the adapter lists
  local phy; phy=$(basename "$(readlink -f "/sys/class/net/$1/phy80211" 2>/dev/null)" 2>/dev/null) || { echo 0; return; }
  iw phy "$phy" info 2>/dev/null | grep -E "\* (59[5-9][0-9]|6[0-9]{3}|70[0-9]{2}|71[01][0-9])(\.0)? MHz" |
    { if [ "$2" = enabled ]; then grep -vc disabled; else grep -c .; fi; } || true
}

# Country / regulatory domain. Without a valid country the kernel uses the "world" rules (00), which disable 6 GHz.
regdomain_setup() {
  local ifaces=$1 tz=$2 reg cur n can6=0 g chans applied=0
  echo
  echo "Country / regulatory domain (6 GHz needs one):"
  command -v iw >/dev/null || { echo "    'iw' is not installed on this machine."; yes_no "    Install iw now (uses sudo)?" y && install_pkgs iw || true; }
  cur=$(env_val WIFI_REGDOMAIN)
  reg=$(ask "WIFI_REGDOMAIN (two-letter country code)" "${cur:-$(country_from_tz "$tz")}")
  reg=$(echo "$reg" | tr '[:lower:]' '[:upper:]')
  if [ -n "$reg" ] && ! [[ $reg =~ ^[A-Z]{2}$ ]]; then echo "    '$reg' is not a two-letter country code; leaving it empty."; reg=""; fi
  set_key WIFI_REGDOMAIN "$reg"

  for n in ${ifaces//,/ }; do [ "$(six_ghz "$n" all)" -gt 0 ] && can6=1; done
  chans=$(env_val WIFI_CHANNELS)
  if [ "$can6" = 1 ] && ! [[ ${chans:-default} =~ (6ghz|6all|6g|all|(^|,)6(,|$)) ]]; then
    yes_no "    Your adapter supports 6 GHz. Also scan 6 GHz (WIFI_CHANNELS=${chans:-default},6ghz)?" y &&
      set_key WIFI_CHANNELS "${chans:-default},6ghz"
  fi
  command -v iw >/dev/null || { echo "    Skipping the regulatory checks (no iw)."; return; }

  if ! regdb_present; then
    echo "    ! No regulatory database (regulatory.db) on this machine: the kernel can't apply any country and"
    echo "      stays on 00, which disables 6 GHz."
    if yes_no "    Install wireless-regdb now (uses sudo)?" y && install_pkgs wireless-regdb; then
      as_root iw reg reload 2>/dev/null || true
    fi
  fi
  g=$(global_country)
  echo "    Current country: ${g:-unknown}"
  if [ -n "$reg" ] && [ "$g" != "$reg" ]; then
    if yes_no "    Apply $reg now ('iw reg set $reg', uses sudo)? yolo also applies it at every start" y; then
      as_root iw reg set "$reg" || true
      applied=1
      sleep 2
      g=$(global_country)
      echo "    Country is now: ${g:-unknown}"
    fi
  fi
  if [ "$g" = "00" ] && [ "$applied" = 0 ] && [ -n "$reg" ]; then
    echo "    Still 00 for now; yolo applies $reg when it starts. If yolo then warns that it is still 00,"
    echo "    run: ./scripts/configure.sh --regdomain"
  elif [ "$g" = "00" ]; then
    echo "    ! Still 00 (world rules): 6 GHz stays disabled."
    if ! regdb_present; then echo "      Install the wireless-regdb package, reboot, and run: ./scripts/configure.sh --regdomain"
    elif [ -n "$reg" ]; then echo "      The kernel didn't take $reg: reboot so it loads the regulatory database, then run this again."
    else echo "      Set WIFI_REGDOMAIN to your country code."; fi
  elif [ -z "$reg" ]; then
    echo "    ! No WIFI_REGDOMAIN set: yolo can't make sure the country is right after a reboot."
  fi
  for n in ${ifaces//,/ }; do
    [ "$(six_ghz "$n" all)" -gt 0 ] || continue
    echo "    $n: $(six_ghz "$n" enabled) of $(six_ghz "$n" all) 6 GHz channels enabled"
  done
  return 0
}

if [ "${1:-}" = "--regdomain" ]; then
  wifi_now=$(env_val WIFI_INTERFACES)
  [ -n "$wifi_now" ] || { echo "WIFI_INTERFACES is empty in .env: run ./scripts/configure.sh first."; exit 1; }
  regdomain_setup "$wifi_now" "$(env_val TZ)"
  echo
  echo "Restart yolo to apply:  docker compose restart yolo"
  exit 0
fi

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
[ -n "$wifi_val" ] && regdomain_setup "$wifi_val" "$tz_val"

for n in ${wifi_val//,/ } ${eth_val//,/ }; do
  [ "$n" = "$default_if" ] && echo "WARNING: $n carries this machine's own network connection; capturing on it can cut you off."
done
echo
echo "Saved to $(pwd)/.env:"
grep -E "^(WIFI_INTERFACES|WIFI_CHANNELS|WIFI_REGDOMAIN|ETH_INTERFACES|BT_DEVICES|TZ)=" .env | sed 's/^/    /'
echo
echo "Start yolo with:  docker compose up -d --build"
