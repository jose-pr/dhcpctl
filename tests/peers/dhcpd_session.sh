#!/bin/sh
# A real ISC dhcpd with OMAPI on 127.0.0.1:7911, and a DHCP client, in network
# namespaces of the caller's own: run as `unshare -rn sh dhcpd_session.sh MAC
# KEY OUTDIR STEP...`. KEY is the base64 HMAC-MD5 secret of the OMAPI key
# `omapi_key`. A STEP is `lease` or `lease:<user class>`, a DHCP exchange
# (the second sending option 77 as that flat string, as iPXE does) whose result
# goes to OUTDIR/lease<N> as udhcpc's variables, one per line, or NO-LEASE; any
# other STEP is a shell command run with dhcpd up, and a failing one ends the
# session with its status. dhcpd's own log is OUTDIR/dhcpd.log.
set -eu
MAC=$1 KEY=$2 OUT=$3
shift 3
WORK=$(mktemp -d)
trap 'kill "$SERVER" "$CLIENT" 2>/dev/null || true; rm -rf "$WORK"' EXIT
SERVER= CLIENT=

ip link set lo up
ip link add srv type veth peer name cli
ip link set cli address "$MAC"
ip addr add 10.0.0.1/24 dev srv
ip link set srv up
unshare -n sleep 300 &
CLIENT=$!
sleep 0.2
ip link set cli netns "$CLIENT"

cat >"$WORK/dhcpd.conf" <<EOF
omapi-port 7911;
key omapi_key { algorithm hmac-md5; secret "$KEY"; };
omapi-key omapi_key;
authoritative;
default-lease-time 600;
subnet 10.0.0.0 netmask 255.255.255.0 { range 10.0.0.100 10.0.0.200; }
EOF
touch "$WORK/leases"
dhcpd -f -d -4 -cf "$WORK/dhcpd.conf" -lf "$WORK/leases" -pf "$WORK/pid" srv \
  >"$OUT/dhcpd.log" 2>&1 &
SERVER=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  grep -q "Sending on" "$OUT/dhcpd.log" 2>/dev/null && break
  sleep 0.3
done

cat >"$WORK/script" <<'EOF'
#!/bin/sh
[ "$1" = bound ] || exit 0
env | grep -E '^(ip|siaddr|sname|boot_file|bootfile|tftp|router|dns|domain|hostname|opt[0-9]+)=' | sort >"$LEASE"
EOF
chmod +x "$WORK/script"

exchange() {
  # $1: the user class to send, or nothing.
  CLASS=
  if [ -n "$1" ]; then
    CLASS="-x 0x4d:$(printf %s "$1" | od -An -tx1 | tr -d ' \n')"
  fi
  nsenter -t "$CLIENT" -n sh -c 'ip link set lo up; ip link set cli up;
    udhcpc -i cli -n -q -R -f -t 3 -T 1 -s "$0" $1 >/dev/null 2>&1' \
    "$WORK/script" "$CLASS" || true
}

n=0
for step in "$@"; do
  case "$step" in
  lease | lease:*)
    n=$((n + 1))
    LEASE="$OUT/lease$n"
    export LEASE
    echo NO-LEASE >"$LEASE"
    case "$step" in lease:*) exchange "${step#lease:}" ;; *) exchange "" ;; esac
    ;;
  *)
    sh -c "$step"
    ;;
  esac
done
