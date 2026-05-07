#!/bin/bash
# Скрипт проведения эксперимента
# Использование: ./experiment.sh <сценарий> <транспорт> <длительность>
# Пример: ./experiment.sh loss_2 tcp 60

set -e

SCENARIO=$1    # baseline, loss_1, loss_2, loss_5, jitter, bandwidth, combo
TRANSPORT=$2   # tcp, quic
DURATION=$3    # секунды
IFACE=${4:-enp0s3}  # сетевой интерфейс, по умолчанию enp0s3

RESULTS_DIR="results/$(date +%Y%m%d_%H%M%S)_${SCENARIO}_${TRANSPORT}"
mkdir -p "$RESULTS_DIR"

echo "=== Эксперимент: $SCENARIO / $TRANSPORT / ${DURATION}s ==="

# Функция очистки tc при выходе
cleanup() {
    echo "Убираем tc правила..."
    sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
}
trap cleanup EXIT

# Применяем сетевые условия
apply_scenario() {
    # Сначала убираем предыдущие правила
    sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true

    case "$SCENARIO" in
        baseline)
            echo "Сеть: нормальная (без ограничений)"
            ;;
        loss_1)
            echo "Сеть: потери 1%"
            sudo tc qdisc add dev "$IFACE" root netem loss 1%
            ;;
        loss_2)
            echo "Сеть: потери 2%"
            sudo tc qdisc add dev "$IFACE" root netem loss 2%
            ;;
        loss_5)
            echo "Сеть: потери 5%"
            sudo tc qdisc add dev "$IFACE" root netem loss 5%
            ;;
        jitter)
            echo "Сеть: джиттер 50ms ± 30ms"
            sudo tc qdisc add dev "$IFACE" root netem delay 50ms 30ms distribution normal
            ;;
        bandwidth)
            echo "Сеть: ограничение 1 Mbit/s"
            sudo tc qdisc add dev "$IFACE" root tbf rate 1mbit burst 32kbit latency 400ms
            ;;
        combo)
            echo "Сеть: потери 2% + джиттер 30ms"
            sudo tc qdisc add dev "$IFACE" root netem delay 30ms 10ms loss 2%
            ;;
        *)
            echo "Неизвестный сценарий: $SCENARIO"
            exit 1
            ;;
    esac
}

# Запускаем захват трафика
start_capture() {
    local port
    if [ "$TRANSPORT" = "tcp" ]; then
        port=9001
    else
        port=9002
    fi

    echo "Захват трафика на порту $port -> $RESULTS_DIR/capture.pcap"

    sudo bash -c "exec tcpdump -i '$IFACE' port '$port' \
        -U -s 0 -B 4096 \
        -w '$RESULTS_DIR/capture.pcap'" &
    TCPDUMP_PID=$!

    echo $TCPDUMP_PID > "$RESULTS_DIR/tcpdump.pid"
    sleep 1
}

# Собираем системные метрики
start_metrics() {
    # CPU и память каждую секунду
    pidstat -u 1 "$DURATION" > "$RESULTS_DIR/cpu.txt" &
    
    # Сетевой трафик
    sar -n DEV 1 "$DURATION" > "$RESULTS_DIR/network.txt" &
    
    echo "Сбор метрик запущен"
}

stop_capture() {
    if [ -f "$RESULTS_DIR/tcpdump.pid" ]; then
        local pid
        pid=$(cat "$RESULTS_DIR/tcpdump.pid")

        sudo kill -INT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

# Сохраняем параметры эксперимента
save_params() {
    cat > "$RESULTS_DIR/params.json" << EOF
{
    "scenario": "$SCENARIO",
    "transport": "$TRANSPORT",
    "duration": $DURATION,
    "interface": "$IFACE",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# Основной flow
apply_scenario
start_capture
start_metrics
save_params

echo ""
echo "Всё готово. Теперь:"
echo "  1. Подключись через mstsc на localhost:13389"
echo "  2. Работай в RDP сессии $DURATION секунд"
echo "  3. Нажми Enter когда закончишь"
echo ""
read -p "Нажми Enter для завершения эксперимента..."

stop_capture

echo ""
echo "Результаты сохранены в $RESULTS_DIR/"
echo "Файлы:"
echo "  capture.pcap  — трафик для Wireshark"
echo "  cpu.txt       — нагрузка CPU"
echo "  network.txt   — сетевой трафик"
echo "  params.json   — параметры эксперимента"