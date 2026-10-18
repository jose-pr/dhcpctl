#!/bin/sh
# A real Kea (kea-dhcp4 with the host_cmds and class_cmds hooks, behind
# kea-ctrl-agent on 127.0.0.1:8000) and a DHCP client, in network namespaces of
# the caller's own: run as `unshare -rn sh kea_session.sh MAC OUTDIR STEP...`.
# A STEP is `lease` or `lease:<user class>`, a DHCP exchange (the second sending
# option 77 as that flat string, as iPXE does) whose result goes to
# OUTDIR/lease<N> as udhcpc's variables, one per line, or NO-LEASE; any other
# STEP is a shell command run with Kea up, and a failing one ends the session
# with its status. Kea's logs are OUTDIR/kea-dhcp4.log and OUTDIR/kea-ca.log.
# The client also asks for each option code in $ASK.
set -eu
MAC=$1 OUT=$2
shift 2
WORK=$(mktemp -d)
trap 'kill "$DHCP4" "$AGENT" "$CLIENT" 2>/dev/null || true; rm -rf "$WORK"' EXIT
DHCP4= AGENT= CLIENT=
# Kea keeps its sockets, data and pid files where these say, not under /run.
export KEA_CONTROL_SOCKET_DIR="$WORK" KEA_DHCP_DATA_DIR="$WORK" \
  KEA_LOG_FILE_DIR="$WORK" KEA_PIDFILE_DIR="$WORK" KEA_LOCKFILE_DIR="$WORK"

ip link set lo up
ip link add srv type veth peer name cli
ip link set cli address "$MAC"
ip addr add 10.0.0.1/24 dev srv
ip link set srv up
unshare -n sleep 300 &
CLIENT=$!
sleep 0.2
ip link set cli netns "$CLIENT"
# Kea opens its socket only on a running link, which needs both ends up.
nsenter -t "$CLIENT" -n ip link set cli up

cat >"$WORK/dhcp4.json" <<EOF
{"Dhcp4": {
  "interfaces-config": {"interfaces": ["srv"]},
  "control-socket": {"socket-type": "unix", "socket-name": "$WORK/dhcp4.sock"},
  "lease-database": {"type": "memfile", "persist": false},
  "valid-lifetime": 600,
  "hooks-libraries": [
    {"library": "/usr/lib64/kea/hooks/libdhcp_host_cmds.so"},
    {"library": "/usr/lib64/kea/hooks/libdhcp_class_cmds.so"}
  ],
  "subnet4": [{"id": 1, "subnet": "10.0.0.0/24",
               "pools": [{"pool": "10.0.0.100-10.0.0.200"}]}],
  "loggers": [{"name": "kea-dhcp4", "severity": "INFO",
               "output-options": [{"output": "stdout"}]}]
}}
EOF
cat >"$WORK/agent.json" <<EOF
{"Control-agent": {
  "http-host": "127.0.0.1", "http-port": 8000,
  "control-sockets": {"dhcp4": {"socket-type": "unix", "socket-name": "$WORK/dhcp4.sock"}},
  "loggers": [{"name": "kea-ctrl-agent", "severity": "INFO",
               "output-options": [{"output": "stdout"}]}]
}}
EOF
kea-dhcp4 -c "$WORK/dhcp4.json" >"$OUT/kea-dhcp4.log" 2>&1 &
DHCP4=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S "$WORK/dhcp4.sock" ] && break
  sleep 0.3
done
kea-ctrl-agent -c "$WORK/agent.json" >"$OUT/kea-ca.log" 2>&1 &
AGENT=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  grep -q "HTTP control channel" "$OUT/kea-ca.log" 2>/dev/null && break
  sleep 0.3
done

cat >"$WORK/script" <<'EOF'
#!/bin/sh
[ "$1" = bound ] || exit 0
env | grep -E '^(ip|siaddr|sname|boot_file|bootfile|tftp|router|dns|domain|hostname|timezone|mtu|ipttl|search|ntpsrv|opt[0-9]+)=' | sort >"$LEASE"
EOF
chmod +x "$WORK/script"

exchange() {
  # $1: the user class to send, or nothing.
  CLASS=
  for code in ${ASK:-}; do CLASS="$CLASS -O $code"; done
  if [ -n "$1" ]; then
    CLASS="$CLASS -x 0x4d:$(printf %s "$1" | od -An -tx1 | tr -d ' \n')"
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
