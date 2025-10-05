#!/usr/bin/env python3

import argparse
import logging
from prometheus_client import start_http_server, Counter, Gauge, Enum, Info, REGISTRY
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, InfoMetricFamily
from protocol import Protocol
from network import Network, InterfaceProblem

logger = logging.getLogger(__name__)

class TPLinkSwitchCollector:
    """Prometheus collector for TP-Link Easy Smart Switch metrics.

    This collector queries the switch on each Prometheus scrape request.
    """

    # Link status mapping from the web UI
    LINK_STATUS = {
        0: 'link_down',
        1: 'auto',
        2: '10m_half',
        3: '10m_full',
        4: '100m_half',
        5: '100m_full',
        6: '1000m_full',
        7: 'unknown'
    }

    def __init__(self, interface, switch_mac, username, password):
        self.interface = interface
        self.switch_mac = switch_mac
        self.username = username
        self.password = password

    def collect(self):
        """Called by Prometheus client on each scrape request."""
        try:
            # Connect to switch
            net = Network(self.interface, self.switch_mac)
            net.login(self.username, self.password)

            # Get switch info (hostname query)
            logger.debug("Fetching switch info...")
            header, payload = net.query(
                Protocol.GET,
                [(Protocol.get_id('hostname'), b'')]
            )

            # Parse switch info and create info metric
            info = {item[1]: str(item[2]) for item in payload
                   if item[1] in ['type', 'hostname', 'mac', 'firmware', 'hardware']}

            switch_info = InfoMetricFamily(
                'tplink_switch',
                'TP-Link switch information'
            )
            switch_info.add_metric([], info)
            yield switch_info

            logger.info(f"Scraping switch: {info.get('hostname', 'unknown')} ({info.get('type', 'unknown')})")

            # Get VLAN configuration
            logger.debug("Fetching VLAN configuration...")
            header, vlan_payload = net.query(
                Protocol.GET,
                [(Protocol.get_id('vlan'), b'')]
            )

            # Get PVID configuration
            logger.debug("Fetching PVID configuration...")
            header, pvid_payload = net.query(
                Protocol.GET,
                [(Protocol.get_id('pvid'), b'')]
            )

            # Get port statistics
            logger.debug("Fetching port statistics...")
            header, payload = net.query(
                Protocol.GET,
                [(Protocol.get_id('stats'), b'')]
            )

            # Create metric families
            port_info = InfoMetricFamily(
                'tplink_port',
                'Port information including state, link status, and up status',
                labels=['port']
            )

            port_tx_good = CounterMetricFamily(
                'tplink_port_tx_good_packets',
                'Total good packets transmitted',
                labels=['port']
            )

            port_tx_bad = CounterMetricFamily(
                'tplink_port_tx_bad_packets',
                'Total bad packets transmitted',
                labels=['port']
            )

            port_rx_good = CounterMetricFamily(
                'tplink_port_rx_good_packets',
                'Total good packets received',
                labels=['port']
            )

            port_rx_bad = CounterMetricFamily(
                'tplink_port_rx_bad_packets',
                'Total bad packets received',
                labels=['port']
            )

            port_pvid = GaugeMetricFamily(
                'tplink_port_pvid',
                'Port VLAN ID (default VLAN for untagged traffic)',
                labels=['port']
            )

            vlan_enabled = GaugeMetricFamily(
                'tplink_vlan_enabled',
                'Whether VLANs are enabled on the switch',
                labels=[]
            )

            vlan_info = InfoMetricFamily(
                'tplink_vlan',
                'VLAN name and configuration',
                labels=['vlan_id']
            )

            vlan_member = GaugeMetricFamily(
                'tplink_vlan_member',
                'VLAN membership per port (1=member, 0=not member)',
                labels=['vlan_id', 'port', 'tagged']
            )

            # Parse and export VLAN data
            for item in vlan_payload:
                if item[1] == 'vlan_enabled':
                    # '01' means enabled, '00' means disabled
                    enabled = 1 if item[2] == '01' else 0
                    vlan_enabled.add_metric([], enabled)
                    logger.debug(f"VLANs enabled: {enabled}")
                elif item[1] == 'vlan':
                    # VLAN format: [vlan_id, member_ports, tagged_ports, vlan_name]
                    vlan_id, member_ports, tagged_ports, vlan_name = item[2]

                    # Add VLAN info (just name)
                    vlan_info.add_metric(
                        [str(vlan_id)],
                        {'name': vlan_name}
                    )

                    # Parse member and tagged ports
                    member_set = set(member_ports.split(',')) if member_ports else set()
                    tagged_set = set(tagged_ports.split(',')) if tagged_ports else set()

                    # Add a metric for each port's membership
                    for port in member_set:
                        is_tagged = 'true' if port in tagged_set else 'false'
                        vlan_member.add_metric(
                            [str(vlan_id), port, is_tagged],
                            1
                        )

                    logger.debug(f"VLAN {vlan_id} ({vlan_name}): {len(member_set)} members, {len(tagged_set)} tagged")

            # Parse and export PVID data
            for item in pvid_payload:
                if item[1] == 'pvid':
                    # PVID format: (port, vlan_id)
                    port, vlan_id = item[2]
                    port_pvid.add_metric([str(port)], vlan_id)
                    logger.debug(f"Port {port} PVID: {vlan_id}")

            # Parse and export stats
            # Stats tuple: (port, state, link_status, tx_good, tx_bad, rx_good, rx_bad)
            for item in payload:
                if item[1] == 'stats':
                    port, state, link_status, tx_good, tx_bad, rx_good, rx_bad = item[2]
                    port_label = str(port)

                    # Port is "up" if link_status is not 0 (link_down)
                    is_up = 'true' if link_status != 0 else 'false'
                    status_name = self.LINK_STATUS.get(link_status, 'unknown')
                    state_name = 'enabled' if state == 1 else 'disabled'

                    # Combine port state, link status, and up status into one info metric
                    port_info.add_metric(
                        [port_label],
                        {
                            'state': state_name,
                            'link_status': status_name,
                            'up': is_up
                        }
                    )

                    port_tx_good.add_metric([port_label], tx_good)
                    port_tx_bad.add_metric([port_label], tx_bad)
                    port_rx_good.add_metric([port_label], rx_good)
                    port_rx_bad.add_metric([port_label], rx_bad)

                    logger.debug(f"Port {port}: {state_name}, {status_name}, up={is_up}, "
                               f"TX={tx_good}/{tx_bad}, RX={rx_good}/{rx_bad}")

            # Yield all metrics
            yield vlan_enabled
            yield vlan_info
            yield vlan_member
            yield port_pvid
            yield port_info
            yield port_tx_good
            yield port_tx_bad
            yield port_rx_good
            yield port_rx_bad

            vlan_count = len([p for p in vlan_payload if p[1] == 'vlan'])
            port_count = len([p for p in payload if p[1] == 'stats'])
            logger.info(f"Successfully scraped {port_count} ports, {vlan_count} VLANs")

        except Exception as e:
            logger.error(f"Error collecting metrics: {e}", exc_info=True)
            # Don't re-raise - Prometheus will mark scrape as failed but continue

def main():
    parser = argparse.ArgumentParser(
        description='Prometheus exporter for TP-Link Easy Smart Switch'
    )
    parser.add_argument('--interface', '-i', required=True,
                       help='Network interface to use')
    parser.add_argument('--switch-mac', '-s', required=True,
                       help='MAC address of the switch')
    parser.add_argument('--username', '-u', default='admin',
                       help='Switch username (default: admin)')
    parser.add_argument('--password', '-p', required=True,
                       help='Switch password')
    parser.add_argument('--port', type=int, default=9101,
                       help='HTTP port for metrics endpoint (default: 9101)')
    parser.add_argument('--loglevel', '-l', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Log level (default: INFO)')
    parser.add_argument('--disable-default-metrics', action='store_true',
                       help='Disable default Python/process metrics')
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.loglevel),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Disable default collectors if requested
    if args.disable_default_metrics:
        from prometheus_client import PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR
        REGISTRY.unregister(PROCESS_COLLECTOR)
        REGISTRY.unregister(PLATFORM_COLLECTOR)
        REGISTRY.unregister(GC_COLLECTOR)
        logger.info("Disabled default Python/process metrics")

    # Register the collector
    collector = TPLinkSwitchCollector(
        args.interface,
        args.switch_mac,
        args.username,
        args.password
    )
    REGISTRY.register(collector)

    # Start HTTP server for Prometheus
    start_http_server(args.port)
    logger.info(f"Prometheus exporter started on port {args.port}")
    logger.info(f"Metrics available at http://localhost:{args.port}/metrics")
    logger.info(f"Switch will be queried on each scrape request")

    # Keep the server running
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")

if __name__ == "__main__":
    main()
