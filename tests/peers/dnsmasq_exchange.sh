#!/bin/sh
# One DHCP exchange between a real dnsmasq and a real client, in network
# namespaces of the caller's own: run as `unshare -rn sh dnsmasq_exchange.sh
# HOSTS OPTS MAC OUT`. HOSTS and OPTS are what dnsmasq reads as
# --dhcp-hostsfile and --dhcp-optsfile (a file or a directory). OUT receives
# what the client was given (udhcpc's variables, one per line), or NO-LEASE,
# then dnsmasq's own log after a `--- dnsmasq` line.
set -eu
HOSTS=$1 OPTS=$2 MAC=$3 OUT=$4
WORK=$(mktemp -d)
trap 'kill "$SERVER" "$CLIENT" 2>/dev/null || true; rm -rf "$WORK"' EXIT
SERVER= CLIENT=

ip link set lo up
ip link add srv type veth peer name cli
ip link set cli address "$MAC"
ip addr add 10.0.0.1/24 dev srv
ip link set srv up
# The client end lives in a namespace of its own, so its broadcast reaches
# the server through the pair rather than over the local routes.
unshare -n sleep 60 &
CLIENT=$!
sleep 0.2
ip link set cli netns "$CLIENT"

dnsmasq -d -C /dev/null --port=0 --user=root --interface=srv --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0 \
  --dhcp-leasefile="$WORK/leases" --dhcp-hostsfile="$HOSTS" --dhcp-optsfile="$OPTS" \
  >"$WORK/dnsmasq.log" 2>&1 &
SERVER=$!
sleep 0.5

# boot_file is the BOOTP file field, bootfile option 67, siaddr the next server.
cat >"$WORK/script" <<'EOF'
#!/bin/sh
[ "$1" = bound ] || exit 0
env | grep -E '^(ip|siaddr|sname|boot_file|bootfile|tftp|router|dns|domain|hostname|opt[0-9]+)=' | sort >"$OUT"
EOF
chmod +x "$WORK/script"
echo NO-LEASE >"$OUT"
export OUT
nsenter -t "$CLIENT" -n sh -c 'ip link set lo up; ip link set cli up;
  udhcpc -i cli -n -q -f -t 3 -T 1 -s "$0" >/dev/null 2>&1' "$WORK/script" || true

echo "--- dnsmasq" >>"$OUT"
cat "$WORK/dnsmasq.log" >>"$OUT"
