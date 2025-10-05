#!/usr/bin/env python3

import argparse
import logging
import socket
import random

from protocol import Protocol
from binary import mac_to_bytes

logger = logging.getLogger(__name__)

class UnicastNetwork:
    """Test version of Network that uses unicast instead of broadcast"""

    UDP_SEND_TO_PORT = 29808
    UDP_RECEIVE_FROM_PORT = 29809
    BROADCAST_ADDR = "255.255.255.255"

    def __init__(self, interface_ip, switch_mac, switch_ip):
        self.interface_ip = interface_ip
        self.switch_mac = switch_mac
        self.switch_ip = switch_ip
        self.sequence_id = random.randint(0, 1000)

        self.header = Protocol.header["blank"].copy()
        self.header.update({
            'sequence_id': self.sequence_id,
            'host_mac': b'\x00\x00\x00\x00\x00\x00',  # We don't need real host MAC
            'switch_mac': mac_to_bytes(self.switch_mac),
        })

        # Sending socket - bind to interface IP
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.ss.bind((self.interface_ip, self.UDP_RECEIVE_FROM_PORT))

        # Receiving socket
        self.rs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rs.bind((self.BROADCAST_ADDR, self.UDP_RECEIVE_FROM_PORT))
        self.rs.settimeout(5)

    def send(self, op_code, payload, use_unicast=True):
        self.sequence_id = (self.sequence_id + 1) % 1000
        self.header.update({
            'sequence_id': self.sequence_id,
            'op_code': op_code,
        })
        packet = Protocol.assemble_packet(self.header, payload)
        packet = Protocol.encode(packet)

        if use_unicast:
            dest = (self.switch_ip, self.UDP_SEND_TO_PORT)
            logger.info(f"Sending UNICAST to {dest}")
        else:
            dest = (self.BROADCAST_ADDR, self.UDP_SEND_TO_PORT)
            logger.info(f"Sending BROADCAST to {dest}")

        self.ss.sendto(packet, dest)
        logger.debug(f"Sent packet: op_code={op_code}, seq={self.sequence_id}")

    def receive(self):
        try:
            data, addr = self.rs.recvfrom(1500)
            logger.debug(f"Received packet from {addr}")
        except socket.timeout:
            logger.error("Timeout waiting for response")
            return None, None

        if data:
            data = Protocol.decode(data)
            header, payload = Protocol.split(data)
            header, payload = Protocol.interpret_header(header), Protocol.interpret_payload(payload)
            self.header['token_id'] = header['token_id']
            logger.debug(f"Received: seq={header['sequence_id']}, payload items={len(payload)}")
            return header, payload
        return None, None

    def query(self, op_code, payload, use_unicast=True):
        self.send(op_code, payload, use_unicast=use_unicast)
        expected_seq = self.sequence_id

        # Try to receive matching response
        max_attempts = 10
        for attempt in range(max_attempts):
            header, payload = self.receive()
            if header is None:
                return None, None
            if header['sequence_id'] == expected_seq:
                return header, payload
            logger.debug(f"Received seq {header['sequence_id']}, expecting {expected_seq}, retrying...")

        logger.error(f"Did not receive matching response after {max_attempts} attempts")
        return None, None

    def login(self, username, password, use_unicast=True):
        header, payload = self.query(
            Protocol.GET,
            [(Protocol.get_id("get_token_id"), b'')],
            use_unicast=use_unicast
        )
        if header is None:
            return False

        login_payload = [
            (Protocol.get_id('username'), username.encode('ascii') + b'\x00'),
            (Protocol.get_id('password'), password.encode('ascii') + b'\x00'),
        ]
        header, payload = self.query(Protocol.LOGIN, login_payload, use_unicast=use_unicast)
        return header is not None


def test_unicast(interface_ip, switch_ip, switch_mac, username, password):
    """Test unicast communication with the switch"""

    print(f"\n{'='*60}")
    print(f"Testing UNICAST to {switch_ip} (MAC: {switch_mac})")
    print(f"{'='*60}\n")

    net = UnicastNetwork(interface_ip, switch_mac, switch_ip)

    # Test login
    print("1. Testing login with UNICAST...")
    if not net.login(username, password, use_unicast=True):
        print("   ❌ UNICAST login failed")
        return False
    print("   ✓ UNICAST login successful")

    # Test hostname query
    print("2. Testing hostname query with UNICAST...")
    header, payload = net.query(
        Protocol.GET,
        [(Protocol.get_id('hostname'), b'')],
        use_unicast=True
    )

    if header is None or not payload:
        print("   ❌ UNICAST hostname query failed")
        return False

    # Extract hostname from payload
    hostname = None
    for item in payload:
        if item[1] == 'hostname':
            hostname = item[2]
            break

    if hostname:
        print(f"   ✓ UNICAST hostname query successful: {hostname}")
    else:
        print("   ❌ No hostname in response")
        return False

    print(f"\n{'='*60}")
    print("✓ UNICAST MODE WORKS!")
    print(f"{'='*60}\n")
    return True


def test_broadcast(interface_ip, switch_ip, switch_mac, username, password):
    """Test broadcast communication (baseline) with the switch"""

    print(f"\n{'='*60}")
    print(f"Testing BROADCAST (baseline)")
    print(f"{'='*60}\n")

    net = UnicastNetwork(interface_ip, switch_mac, switch_ip)

    # Test login
    print("1. Testing login with BROADCAST...")
    if not net.login(username, password, use_unicast=False):
        print("   ❌ BROADCAST login failed")
        return False
    print("   ✓ BROADCAST login successful")

    # Test hostname query
    print("2. Testing hostname query with BROADCAST...")
    header, payload = net.query(
        Protocol.GET,
        [(Protocol.get_id('hostname'), b'')],
        use_unicast=False
    )

    if header is None or not payload:
        print("   ❌ BROADCAST hostname query failed")
        return False

    # Extract hostname from payload
    hostname = None
    for item in payload:
        if item[1] == 'hostname':
            hostname = item[2]
            break

    if hostname:
        print(f"   ✓ BROADCAST hostname query successful: {hostname}")
    else:
        print("   ❌ No hostname in response")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description='Test unicast vs broadcast communication with TP-Link switch'
    )
    parser.add_argument('--interface-ip', '-I', required=True,
                       help='IP address of the interface to bind to')
    parser.add_argument('--switch-ip', '-S', required=True,
                       help='IP address of the switch')
    parser.add_argument('--switch-mac', '-s', required=True,
                       help='MAC address of the switch')
    parser.add_argument('--username', '-u', default='admin',
                       help='Switch username (default: admin)')
    parser.add_argument('--password', '-p', required=True,
                       help='Switch password')
    parser.add_argument('--loglevel', '-l', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Log level (default: INFO)')
    parser.add_argument('--unicast-only', action='store_true',
                       help='Only test unicast (skip broadcast test)')
    parser.add_argument('--broadcast-only', action='store_true',
                       help='Only test broadcast (skip unicast test)')
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.loglevel),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Run tests
    broadcast_works = True
    unicast_works = True

    if not args.unicast_only:
        broadcast_works = test_broadcast(
            args.interface_ip, args.switch_ip, args.switch_mac,
            args.username, args.password
        )

    if not args.broadcast_only:
        unicast_works = test_unicast(
            args.interface_ip, args.switch_ip, args.switch_mac,
            args.username, args.password
        )

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    if not args.unicast_only:
        print(f"Broadcast: {'✓ WORKS' if broadcast_works else '❌ FAILED'}")
    if not args.broadcast_only:
        print(f"Unicast:   {'✓ WORKS' if unicast_works else '❌ FAILED'}")
    print(f"{'='*60}\n")

    if unicast_works and not args.broadcast_only:
        print("🎉 Good news! Unicast mode works. This means:")
        print("   - Less broadcast traffic on your network")
        print("   - Credentials not broadcast to entire subnet")
        print("   - More targeted communication\n")


if __name__ == "__main__":
    main()
