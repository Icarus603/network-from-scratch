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
case "${ACK_ELICITING_THRESHOLD:-1}" in
    *[!0-9]*|"")
        echo "ACK_ELICITING_THRESHOLD must be a positive integer" >&2
        exit 2
        ;;
    0)
        echo "ACK_ELICITING_THRESHOLD must be greater than zero" >&2
        exit 2
        ;;
esac
case "${PACKET_THRESHOLD:-3}" in
    *[!0-9]*|"")
        echo "PACKET_THRESHOLD must be an integer of at least 3" >&2
        exit 2
        ;;
    0|1|2)
        echo "PACKET_THRESHOLD must be at least 3" >&2
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
case "${BETA_FIRST_TIMEOUT_SECS:-60}" in
    *[!0-9]*|"")
        echo "BETA_FIRST_TIMEOUT_SECS must be a positive integer" >&2
        exit 2
        ;;
    0)
        echo "BETA_FIRST_TIMEOUT_SECS must be greater than zero" >&2
        exit 2
        ;;
esac
for window in \
    "${STREAM_RECEIVE_WINDOW_MIB:-64}" \
    "${CONNECTION_RECEIVE_WINDOW_MIB:-256}" \
    "${SEND_WINDOW_MIB:-64}"
do
    case "$window" in
        *[!0-9]*|"")
            echo "QUIC window values must be positive integer MiB" >&2
            exit 2
            ;;
        0)
            echo "QUIC window values must be greater than zero" >&2
            exit 2
            ;;
    esac
done
sed -i \
    "s/^beta_first_timeout_secs:.*/beta_first_timeout_secs: ${BETA_FIRST_TIMEOUT_SECS:-60}/" \
    "$config"
sed -i \
    "s/^beta_brutal_target_mbps:.*/beta_brutal_target_mbps: ${BRUTAL_TARGET_MBPS:-1000}/" \
    "$config"
sed -i \
    "s/^beta_ack_eliciting_threshold:.*/beta_ack_eliciting_threshold: ${ACK_ELICITING_THRESHOLD:-1}/" \
    "$config"
sed -i \
    -e "s/^beta_packet_threshold:.*/beta_packet_threshold: ${PACKET_THRESHOLD:-3}/" \
    -e "s/^beta_time_threshold:.*/beta_time_threshold: ${TIME_THRESHOLD:-1.125}/" \
    "$config"
sed -i "s/^beta_initial_mtu:.*/beta_initial_mtu: ${INITIAL_MTU:-1350}/" "$config"
sed -i "s/^beta_minimum_mtu:.*/beta_minimum_mtu: ${MINIMUM_MTU:-1350}/" "$config"
sed -i \
    "s/^beta_mtu_upper_bound:.*/beta_mtu_upper_bound: ${MTU_UPPER_BOUND:-1452}/" \
    "$config"
sed -i \
    "s/^beta_stream_receive_window_mib:.*/beta_stream_receive_window_mib: ${STREAM_RECEIVE_WINDOW_MIB:-64}/" \
    "$config"
sed -i \
    "s/^beta_connection_receive_window_mib:.*/beta_connection_receive_window_mib: ${CONNECTION_RECEIVE_WINDOW_MIB:-256}/" \
    "$config"
sed -i \
    "s/^beta_send_window_mib:.*/beta_send_window_mib: ${SEND_WINDOW_MIB:-64}/" \
    "$config"

exec proteus-client run --config "$config"
