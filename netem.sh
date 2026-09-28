#!/usr/bin/env bash
# Порча сети ТОЛЬКО на участке клиент <-> Go-сервер. Запускать на машине сервера.
# Трафик сервер <-> агент не трогается (фильтр по IP клиента).
#
#   sudo ./netem.sh set <loss%> [delay_ms_one_way]   # напр. set 2 25  -> RTT +50 мс, 2% потерь в каждую сторону
#   sudo ./netem.sh show                             # счётчики (dropped должен расти)
#   sudo ./netem.sh clear
#
# IF     — интерфейс, на котором у сервера 192.168.56.102 (проверь: ip -br a)
# CLIENT — адрес, с которого приходит клиент (в логах сервера: remote_addr=192.168.56.1:...)
set -euo pipefail
IF="${IF:-enp0s8}"
CLIENT="${CLIENT:-192.168.56.1}"

clear_all() {
  tc qdisc del dev "$IF" root 2>/dev/null || true
  tc qdisc del dev "$IF" ingress 2>/dev/null || true
  tc qdisc del dev ifb0 root 2>/dev/null || true
}

case "${1:-}" in
  set)
    LOSS="${2:?укажи потери в %}"
    DELAY="${3:-25}"
    clear_all
    modprobe ifb numifbs=1
    ip link set dev ifb0 up

    # сервер -> клиент (egress): 4-я полоса prio только для трафика на CLIENT
    tc qdisc add dev "$IF" root handle 1: prio bands 4
    tc qdisc add dev "$IF" parent 1:4 handle 40: netem delay "${DELAY}ms" loss "${LOSS}%" limit 10000
    tc filter add dev "$IF" parent 1:0 protocol ip prio 1 u32 match ip dst "$CLIENT"/32 flowid 1:4

    # клиент -> сервер (ingress): заворачиваем в ifb0 и портим там
    tc qdisc add dev "$IF" handle ffff: ingress
    tc filter add dev "$IF" parent ffff: protocol ip u32 match ip src "$CLIENT"/32 \
       action mirred egress redirect dev ifb0
    tc qdisc add dev ifb0 root netem delay "${DELAY}ms" loss "${LOSS}%" limit 10000

    echo "netem: $IF, клиент $CLIENT, delay ${DELAY}ms в каждую сторону, loss ${LOSS}% в каждую сторону"
    ;;
  show)
    tc -s qdisc show dev "$IF"
    tc -s qdisc show dev ifb0 2>/dev/null || true
    ;;
  clear)
    clear_all
    echo "netem снят"
    ;;
  *)
    sed -n '2,9p' "$0"; exit 1 ;;
esac
