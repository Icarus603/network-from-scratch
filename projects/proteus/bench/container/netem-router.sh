#!/bin/sh
set -eu

CLIENT_CIDR="${CLIENT_CIDR:-10.77.1.2/24}"
SERVER_CIDR="${SERVER_CIDR:-10.77.2.2/24}"

interface_for_cidr() {
    cidr="$1"
    ip -o -4 addr show | awk -v cidr="$cidr" '$4 == cidr { print $2; exit }'
}

CLIENT_IFACE="$(interface_for_cidr "$CLIENT_CIDR")"
SERVER_IFACE="$(interface_for_cidr "$SERVER_CIDR")"

if [ -z "$CLIENT_IFACE" ] || [ -z "$SERVER_IFACE" ]; then
    echo "netem router could not map both configured CIDRs to interfaces" >&2
    ip -o -4 addr show >&2
    exit 1
fi

# veth offloads can make one qdisc skb represent many QUIC datagrams.
# Disable aggregation/segmentation at the impairment node so netem loss
# probabilities are applied at packet-shaped granularity.
for iface in "$CLIENT_IFACE" "$SERVER_IFACE"; do
    ethtool -K "$iface" gro off gso off tso off
    ethtool -K "$iface" tx-udp-segmentation off 2>/dev/null || true
done

iptables -P FORWARD ACCEPT

mkdir -p /run/proteus-netem
cat > /run/proteus-netem/interfaces.env <<EOF
CLIENT_IFACE=$CLIENT_IFACE
SERVER_IFACE=$SERVER_IFACE
CLIENT_CIDR=$CLIENT_CIDR
SERVER_CIDR=$SERVER_CIDR
EOF

echo "NETEM_ROUTER_READY client_iface=$CLIENT_IFACE server_iface=$SERVER_IFACE"
exec sleep infinity
