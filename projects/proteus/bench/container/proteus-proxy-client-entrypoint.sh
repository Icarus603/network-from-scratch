#!/bin/sh
set -eu

ip route replace 10.77.2.0/24 via 10.77.1.2
test -e /run/proteus-proxy/ready

config=/tmp/proteus-proxy-client.yaml
cp /bench/proteus-proxy-client.yaml "$config"

case "${BRUTAL_TARGET_MBPS:-1000}" in
    *[!0-9]*|"")
        echo "BRUTAL_TARGET_MBPS must be a positive integer" >&2
        exit 2
        ;;
    0)
        echo "BRUTAL_TARGET_MBPS must be greater than zero" >&2
        exit 2
        ;;
esac
case "${ACK_ELICITING_THRESHOLD:-10}" in
    *[!0-9]*|"")
        echo "ACK_ELICITING_THRESHOLD must be a positive integer" >&2
        exit 2
        ;;
    0)
        echo "ACK_ELICITING_THRESHOLD must be greater than zero" >&2
        exit 2
        ;;
esac
case "${INITIAL_MTU:-1350}" in
    *[!0-9]*|"")
        echo "INITIAL_MTU must be a positive integer" >&2
        exit 2
        ;;
    0)
        echo "INITIAL_MTU must be greater than zero" >&2
        exit 2
        ;;
esac
sed -i \
    "s/^beta_brutal_target_mbps:.*/beta_brutal_target_mbps: ${BRUTAL_TARGET_MBPS:-1000}/" \
    "$config"
sed -i \
    "s/^beta_ack_eliciting_threshold:.*/beta_ack_eliciting_threshold: ${ACK_ELICITING_THRESHOLD:-10}/" \
    "$config"
sed -i "s/^beta_initial_mtu:.*/beta_initial_mtu: ${INITIAL_MTU:-1350}/" "$config"
sed -i "s/^beta_minimum_mtu:.*/beta_minimum_mtu: ${MINIMUM_MTU:-1350}/" "$config"
sed -i \
    "s/^beta_mtu_upper_bound:.*/beta_mtu_upper_bound: ${MTU_UPPER_BOUND:-1452}/" \
    "$config"

exec proteus-client run --config "$config"
