#!/bin/sh

[ "$type" = "ip6tables" ] && exit 0
[ "$table" != "mangle" ] && [ "$table" != "nat" ] && exit 0

TAG="100-redirect.sh"
IPT="iptables -w"

local_ip=$(
    ip -4 addr show br0 \
        | awk '/inet /{print $2}' \
        | cut -d/ -f1 \
        | grep -E '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
        | head -n1
)

if [ -z "$local_ip" ]; then
    logger -t "$TAG" "br0 local_ip not found"
    exit 0
fi

ensure_set() {
    ipset create "$1" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null
}

nat_add_prerouting() {
    _proto="$1"
    _set="$2"
    _port="$3"
    if ! $IPT -t nat -C PREROUTING -p "$_proto" \
        -m set --match-set "$_set" dst \
        -j REDIRECT --to-port "$_port" >/dev/null 2>&1
    then
        $IPT -t nat -A PREROUTING -p "$_proto" \
            -m set --match-set "$_set" dst \
            -j REDIRECT --to-port "$_port" >/dev/null 2>&1
    fi
}

nat_del_prerouting() {
    _proto="$1"
    _set="$2"
    _port="$3"
    while $IPT -t nat -D PREROUTING -p "$_proto" \
        -m set --match-set "$_set" dst \
        -j REDIRECT --to-port "$_port" >/dev/null 2>&1
    do
        :
    done
}

# DNS клиентов роутера — на локальный dnsmasq
for protocol in udp tcp; do
    if ! $IPT -t nat -C PREROUTING -p "$protocol" --dport 53 \
        -j DNAT --to-destination "$local_ip" >/dev/null 2>&1
    then
        $IPT -t nat -I PREROUTING -p "$protocol" --dport 53 \
            -j DNAT --to-destination "$local_ip" >/dev/null 2>&1
    fi
done

# Удалить старые некорректные UDP-redirect.
nat_del_prerouting udp unblocktor 9141
nat_del_prerouting udp unblocktroj 10829
nat_del_prerouting udp unblockhysteria 10830

ensure_set unblocksh
nat_add_prerouting tcp unblocksh 1082
nat_add_prerouting udp unblocksh 1082

ensure_set unblocktor
nat_add_prerouting tcp unblocktor 9141

ensure_set unblockvless
nat_add_prerouting tcp unblockvless 10810
nat_add_prerouting udp unblockvless 10810

ensure_set unblocktroj
nat_add_prerouting tcp unblocktroj 10829

ensure_set unblockhysteria
nat_add_prerouting tcp unblockhysteria 10830

ensure_set unblockrouter

if ! $IPT -t nat -C OUTPUT -o lo -j RETURN >/dev/null 2>&1; then
    $IPT -t nat -I OUTPUT -o lo -j RETURN >/dev/null 2>&1
fi

for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    if ! $IPT -t nat -C OUTPUT -d "$net" -j RETURN >/dev/null 2>&1; then
        $IPT -t nat -A OUTPUT -d "$net" -j RETURN >/dev/null 2>&1
    fi
done

for proto in tcp udp; do
    if ! $IPT -t nat -C OUTPUT -p "$proto" \
        -m set --match-set unblockrouter dst \
        -j REDIRECT --to-port 10810 >/dev/null 2>&1
    then
        $IPT -t nat -A OUTPUT -p "$proto" \
            -m set --match-set unblockrouter dst \
            -j REDIRECT --to-port 10810 >/dev/null 2>&1
    fi
done

# VPN ipset -> fwmark
if ls -d /opt/etc/unblock/vpn-*.txt >/dev/null 2>&1; then
    for vpn_file_name in /opt/etc/unblock/vpn-*.txt; do
        [ -f "$vpn_file_name" ] || continue

        vpn_unblock_name=$(basename "$vpn_file_name" .txt)
        unblockvpn="unblock${vpn_unblock_name}"
        vpn_type=$(printf '%s\n' "$unblockvpn" | sed 's/-/ /g' | awk '{print $NF}')
        vpn_link_up=$(curl -s "localhost:79/rci/show/interface/${vpn_type}/link" | tr -d '"')

        [ "$vpn_link_up" = "up" ] || continue

        vpn_type_lower=$(printf '%s' "$vpn_type" | tr '[:upper:]' '[:lower:]')
        vpn_table_id=$(grep -w "$vpn_type_lower" /opt/etc/iproute2/rt_tables | awk '{print $1}' | head -n1)

        [ -n "$vpn_table_id" ] || continue

        vpn_mark_id="0xd${vpn_table_id}"
        ensure_set "$unblockvpn"

        if iptables-save 2>/dev/null | grep -q -- "--match-set $unblockvpn dst"; then
            continue
        fi

        fastnat=$(curl -s localhost:79/rci/show/version | grep ppe)
        software=$(curl -s localhost:79/rci/show/rc/ppe | grep software -C1 | head -1 | awk '{print $2}' | tr -d ",")
        hardware=$(curl -s localhost:79/rci/show/rc/ppe | grep hardware -C1 | head -1 | awk '{print $2}' | tr -d ",")

        logger -t "$TAG" "VPN: $unblockvpn mark=$vpn_mark_id"

        if [ -z "$fastnat" ] && [ "$software" = "false" ] && [ "$hardware" = "false" ]; then
            $IPT -t mangle -A PREROUTING -p tcp \
                -m set --match-set "$unblockvpn" dst \
                -j MARK --set-mark "$vpn_mark_id" >/dev/null 2>&1
            $IPT -t mangle -A PREROUTING -p udp \
                -m set --match-set "$unblockvpn" dst \
                -j MARK --set-mark "$vpn_mark_id" >/dev/null 2>&1
        else
            $IPT -t mangle -A PREROUTING \
                -m conntrack --ctstate NEW \
                -m set --match-set "$unblockvpn" dst \
                -j CONNMARK --set-mark "$vpn_mark_id" >/dev/null 2>&1
            $IPT -t mangle -A PREROUTING \
                -j CONNMARK --restore-mark >/dev/null 2>&1
        fi
    done
fi

exit 0
