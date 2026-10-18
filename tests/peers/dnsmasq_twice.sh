#!/bin/sh
# Two DHCP exchanges with one long-running dnsmasq, and a command between them:
# run as `unshare -rn sh dnsmasq_twice.sh HOSTSDIR OPTSDIR MAC PIDFILE OUT1 OUT2
# COMMAND...`. dnsmasq reads HOSTSDIR and OPTSDIR as --dhcp-hostsdir and
# --dhcp-optsdir and its pid is written to PIDFILE; COMMAND runs after the first
# exchange (it is what changes the files, and whatever reload it does). Each
# OUT is what dnsmasq_exchange.sh writes.
set -eu
HOSTS=$1 OPTS=$2 MAC=$3 PIDFILE=$4 OUT1=$5 OUT2=$6
shift 6
WORK=$(mktemp -d)
trap 'kill "$SERVER" "$CLIENT" 2>/dev/null || true; rm -rf "$WORK"' EXIT
SERVER= CLIENT=

ip link set lo up
ip link add srv type veth peer name cli
ip link set cli address "$MAC"
ip addr add 10.0.0.1/24 dev srv
ip link set srv up
unshare -n sleep 120 &
CLIENT=$!
sleep 0.2
ip link set cli netns "$CLIENT"

dnsmasq -d -C /dev/null --port=0 --user=root --interface=srv --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0 \
  --dhcp-leasefile="$WORK/leases" --dhcp-hostsdir="$HOSTS" --dhcp-optsdir="$OPTS" \
  >"$WORK/dnsmasq.log" 2>&1 &
SERVER=$!
# dnsmasq -d writes no pid file; its pid is the one to signal.
echo "$SERVER" >"$PIDFILE"
sleep 0.5

cat >"$WORK/script" <<'EOF'
#!/bin/sh
[ "$1" = bound ] || exit 0
env | grep -E '^(ip|siaddr|sname|boot_file|bootfile|tftp|router|dns|domain|hostname|opt[0-9]+)=' | sort >"$OUT"
EOF
chmod +x "$WORK/script"

exchange() {
  OUT=$1
  export OUT
  echo NO-LEASE >"$OUT"
  # -R releases the lease on exit, so the next exchange is decided by the
  # reservation files rather than a lease dnsmasq remembers.
  nsenter -t "$CLIENT" -n sh -c 'ip link set lo up; ip link set cli up;
    udhcpc -i cli -n -q -R -f -t 3 -T 1 -s "$0" >/dev/null 2>&1' "$WORK/script" || true
}

exchange "$OUT1"
"$@"
sleep 0.5
exchange "$OUT2"

for out in "$OUT1" "$OUT2"; do
  echo "--- dnsmasq" >>"$out"
  cat "$WORK/dnsmasq.log" >>"$out"
done
