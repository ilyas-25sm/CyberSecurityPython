# Mirza_Firewall.py
import socket
import time
import threading
import psutil
import datetime
import logging

# Импорт пользовательских модулей
from imports.protocols import ethernet_frame, ipv4_packet, icmp_packet, udp_packet, tcp_packet
from imports.helper import get_interfaces, PROTOCOLS
from imports.validator import validate_with_route_table

logging.basicConfig(level=logging.INFO, filename="firewall.log", filemode="w")

# Создание сокета для всех интерфейсов
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Определение режимов файрвола
FULL_ISOLATION = "full_isolation"
SELECTIVE_PROTECTION = "selective_protection"


def send_packet(conn: socket.socket, payload, dst_ip):
    try:
        conn.sendto(payload, (dst_ip, 0))
    except PermissionError as e:
        logging.error(f"Permission Error: {e}")
    except OSError as e:
        logging.error(f"OSError: {e}")


def bind_sockets(interface, mode):
    """
    Запуск прослушивания пакетов.
    """
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    conn.bind((interface[0], 0))
    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            dest_mac, src_mac, eth_protocol, eth_data = ethernet_frame(raw_data)
            if eth_protocol == 8:
                s_addr, d_addr, protocol, ip_header = ipv4_packet(eth_data[14:34])
                logging.info(f"[{datetime.datetime.now()}] {interface[0]} ({s_addr}) > {PROTOCOLS[protocol]}")

                # Блокировка внешнего трафика в режиме полной изоляции
                if mode == FULL_ISOLATION and not is_local(s_addr):
                    logging.warning(f"Blocked external traffic: {s_addr} > {d_addr}")
                    continue

                # Работа в режиме выборочной защиты
                src_port, dst_port = 0, 0
                if protocol == 6:
                    src_port, dst_port = tcp_packet(eth_data[34:54])
                elif protocol == 17:
                    src_port, dst_port, _, _ = udp_packet(eth_data[34:42])

                # Валидация на основе правил в режиме выборочной защиты
                if mode == SELECTIVE_PROTECTION and validate_with_route_table(s_addr, d_addr, src_port, dst_port):
                    send_packet(send_sock, eth_data[14:], d_addr)
                else:
                    logging.error(f"Failed route: {interface[0]} ({s_addr} > {d_addr}) - {PROTOCOLS[protocol]}")
    except KeyboardInterrupt:
        print("Firewall stopped.")
        return


def is_local(ip_address):
    """Проверка, является ли IP локальным."""
    for iface in psutil.net_if_addrs().values():
        for addr in iface:
            if addr.family == socket.AF_INET and ip_address == addr.address:
                return True
    return False


def start_firewall(mode):
    interfaces = get_interfaces()
    if len(interfaces) < 2:
        logging.error("Not enough interfaces")
        return

    for key, val in interfaces.items():
        threading.Thread(target=bind_sockets, args=([key, val], mode), daemon=True).start()
    logging.info(f"FIREWALL IS RUNNING IN {mode.upper()} MODE")
