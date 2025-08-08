import time
import threading
import sqlite3
from pathlib import Path
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, RadioTap
from collections import defaultdict, deque
import statistics
import argparse
import sys

# Try to import TLS layers if available
try:
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import TLSServerName

    TLS_AVAILABLE = True
except ImportError:
    TLS_AVAILABLE = False


class Config:
    # Configuration
    FLOW_TIMEOUT_SECONDS = 15
    CHANNEL_HOP_INTERVAL = 1.0  # seconds between channel changes
    CHANNELS = [1, 6, 11]  # Common non-overlapping channels
    DB_PATH = "network_data.db"  # Path to SQLite database
    IP_RANGE = "192.168.0.0/24"  # Default IP range to monitor
    DATA_SAVE_INTERVAL = 60  # seconds between database saves


# Global State
active_flows = {}
device_data = defaultdict(
    lambda: {
        "last_update": 0,
        "packets_down": 0,
        "packets_up": 0,
        "bytes_down": 0,
        "bytes_up": 0,
        "packet_sizes": deque(maxlen=100),
        "packet_size_list": [],  # List of packet sizes
        "flow_start_time": None,  # Flow start time
        "flow_end_time": None,  # Flow end time
        "last_packet_time": 0,
        "ip": "N/A",
        "payload_sizes": [],  # List of payload sizes
        "server_name_indication": None,  # Server Name Indication
        "client_hello_fingerprint": None,  # Client Hello fingerprint
    }
)

data_lock = threading.Lock()
stop_event = threading.Event()
current_channel = 1  # Start with channel 1


def init_db():
    """Initialize the SQLite database for storing network data."""
    try:
        db_path = Path(Config.DB_PATH)
        db_exists = db_path.exists()

        conn = sqlite3.connect(Config.DB_PATH, check_same_thread=False)
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS network_traffic (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flow_duration REAL,
                packets_to_server INTEGER,
                packets_from_server INTEGER,
                total_bytes_sent INTEGER,
                total_bytes_received INTEGER,
                packet_ratio REAL,
                payload_size_mean REAL,
                iat_mean REAL,
                iat_std REAL,
                burstiness REAL,
                server_name_indication TEXT,
                client_hello_fingerprint TEXT
            )
        """
        )

        conn.commit()
        return conn
    except sqlite3.Error as e:
        print(f"Database initialization error: {str(e)}", file=sys.stderr)
        sys.exit(1)


db_conn = init_db()


def get_wireless_interfaces():
    """Get list of available wireless interfaces."""
    interfaces = []
    for iface in scapy.get_if_list():
        try:
            if "UP" in scapy.get_if_flags(iface):
                if "wlan" in iface.lower() or "wifi" in iface.lower():
                    print(f"Found wireless interface: {iface}")
                    interfaces.append(iface)
        except Exception as e:
            print(f"Error checking interface {iface}: {str(e)}", file=sys.stderr)
    return interfaces


def channel_hopper(interface):
    """Thread function to hop between wireless channels."""
    global current_channel
    channel_index = 0

    while not stop_event.is_set():
        try:
            current_channel = Config.CHANNELS[channel_index % len(Config.CHANNELS)]
            scapy.os.system(f"iwconfig {interface} channel {current_channel}")
            channel_index += 1
            time.sleep(Config.CHANNEL_HOP_INTERVAL)
        except Exception as e:
            print(f"Channel hopping error: {str(e)}", file=sys.stderr)
            time.sleep(1)


class WirelessFlow:
    """Class to track wireless traffic flows between devices."""

    def __init__(self, start_time, packet):
        self.start_time = start_time
        self.last_seen = start_time
        self.packet_count = 0
        self.total_bytes = 0
        self.downstream_bytes = 0
        self.upstream_bytes = 0
        self.packet_sizes = []
        self.payload_sizes = []
        self.iat_sequence = []
        self.server_name_indication = None
        self.client_hello_fingerprint = None

        self.source_mac = packet[Dot11].addr2 if packet.haslayer(Dot11) else None
        self.destination_mac = packet[Dot11].addr1 if packet.haslayer(Dot11) else None
        self.bssid = packet[Dot11].addr3 if packet.haslayer(Dot11) else None
        self.ssid = None
        self.channel = None
        self.signal_strength = None

    def update(self, packet, current_time):
        self.last_seen = current_time
        self.packet_count += 1
        packet_size = len(packet)
        self.total_bytes += packet_size
        self.packet_sizes.append(packet_size)

        # Calculate payload size if available
        if packet.haslayer(scapy.Raw):
            payload_size = len(packet[scapy.Raw].load)
            self.payload_sizes.append(payload_size)

        # Calculate inter-arrival time
        if len(self.packet_sizes) > 1:
            iat = current_time - self.last_seen
            self.iat_sequence.append(iat)

        # Determine direction
        if packet.haslayer(Dot11) and packet.type == 2:  # Data frame
            if packet[Dot11].addr1 == self.bssid:  # To AP
                self.upstream_bytes += packet_size
            else:  # From AP
                self.downstream_bytes += packet_size

        # Update wireless-specific attributes
        if packet.haslayer(Dot11Beacon):
            self.ssid = packet[Dot11Beacon].info.decode("utf-8", errors="ignore")
            self.channel = ord(packet[Dot11Elt:3].info)
        elif packet.haslayer(Dot11ProbeReq):
            self.ssid = packet[Dot11ProbeReq].info.decode("utf-8", errors="ignore")

        if hasattr(packet, "dBm_AntSignal"):
            self.signal_strength = packet.dBm_AntSignal

        # Extract TLS information if available
        if TLS_AVAILABLE and packet.haslayer(TLSClientHello):
            tls = packet[TLSClientHello]
            # Extract Server Name Indication
            for ext in tls.extensions:
                if isinstance(ext, TLSServerName):
                    self.server_name_indication = ext.servername.decode(
                        "utf-8", errors="ignore"
                    )

            # Create a fingerprint from the ClientHello
            fingerprint_parts = [
                str(tls.version),
                str(tls.cipher_suites),
                str([ext.type for ext in tls.extensions]),
            ]
            self.client_hello_fingerprint = "|".join(fingerprint_parts)

    def get_features(self):
        duration = self.last_seen - self.start_time
        duration = max(duration, 0.01)

        iat_mean = statistics.mean(self.iat_sequence) if self.iat_sequence else 0
        iat_std = (
            statistics.stdev(self.iat_sequence) if len(self.iat_sequence) > 1 else 0
        )

        payload_size_mean = (
            statistics.mean(self.payload_sizes) if self.payload_sizes else 0
        )

        return {
            "duration": duration,
            "total_bytes": self.total_bytes,
            "packet_count": self.packet_count,
            "downstream_bytes": self.downstream_bytes,
            "upstream_bytes": self.upstream_bytes,
            "avg_packet_size": (
                statistics.mean(self.packet_sizes) if self.packet_sizes else 0
            ),
            "packets_per_sec": self.packet_count / duration,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "signal_strength": self.signal_strength,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "burstiness": iat_std / iat_mean if iat_mean > 0 else 0,
            "packet_ratio": self.upstream_bytes / max(1, self.downstream_bytes),
            "payload_size_mean": payload_size_mean,
            "server_name_indication": self.server_name_indication,
            "client_hello_fingerprint": self.client_hello_fingerprint,
        }


def process_wireless_packet(packet):
    """Process wireless packets and update device data."""
    try:
        if stop_event.is_set():
            return

        current_time = time.time()

        # Handle data frames (device communication)
        if packet.haslayer(Dot11) and packet.type == 2:  # Data frame
            src_mac = packet[Dot11].addr2
            dst_mac = packet[Dot11].addr1
            bssid = packet[Dot11].addr3
            packet_size = len(packet)

            with data_lock:
                # Update source device
                if src_mac not in device_data:
                    device_data[src_mac] = {
                        "last_update": current_time,
                        "packets_down": 0,
                        "packets_up": 0,
                        "bytes_down": 0,
                        "bytes_up": 0,
                        "packet_sizes": deque(maxlen=100),
                        "packet_size_list": [],
                        "flow_start_time": current_time,
                        "flow_end_time": current_time,
                        "last_packet_time": current_time,
                        "ip": "N/A",
                        "payload_sizes": [],
                        "server_name_indication": None,
                        "client_hello_fingerprint": None,
                    }

                # Update traffic statistics
                if src_mac in device_data:
                    device_data[src_mac]["last_update"] = current_time
                    device_data[src_mac]["last_packet_time"] = current_time
                    device_data[src_mac]["packet_sizes"].append(packet_size)
                    device_data[src_mac]["packet_size_list"].append(packet_size)
                    device_data[src_mac]["flow_end_time"] = current_time

                    # Calculate payload size if available
                    if packet.haslayer(scapy.Raw):
                        payload_size = len(packet[scapy.Raw].load)
                        device_data[src_mac]["payload_sizes"].append(payload_size)

                    # Determine direction of communication
                    if dst_mac == bssid:  # Client to AP (upload)
                        device_data[src_mac]["packets_up"] += 1
                        device_data[src_mac]["bytes_up"] += packet_size
                    else:  # AP to client (download)
                        device_data[src_mac]["packets_down"] += 1
                        device_data[src_mac]["bytes_down"] += packet_size

                    # Extract TLS information if available
                    if TLS_AVAILABLE and packet.haslayer(TLSClientHello):
                        tls = packet[TLSClientHello]
                        # Extract Server Name Indication
                        for ext in tls.extensions:
                            if isinstance(ext, TLSServerName):
                                device_data[src_mac]["server_name_indication"] = (
                                    ext.servername.decode("utf-8", errors="ignore")
                                )

                        # Create a fingerprint from the ClientHello
                        fingerprint_parts = [
                            str(tls.version),
                            str(tls.cipher_suites),
                            str([ext.type for ext in tls.extensions]),
                        ]
                        device_data[src_mac]["client_hello_fingerprint"] = "|".join(
                            fingerprint_parts
                        )

    except Exception as e:
        print(f"Error processing packet: {str(e)}", file=sys.stderr)


def process_packet(packet):
    """Main packet processing function."""
    if stop_event.is_set():
        return

    if packet.haslayer(Dot11):
        process_wireless_packet(packet)


def sniffer_thread_func(interface):
    """Background thread for packet capture."""
    try:
        scapy.sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: stop_event.is_set(),
        )
    except Exception as e:
        print(f"Packet capture error: {str(e)}", file=sys.stderr)


def data_saver_thread_func():
    """Thread to save data to database periodically."""
    while not stop_event.is_set():
        try:
            with data_lock:
                # Save data to database
                cursor = db_conn.cursor()

                for mac, data in device_data.items():
                    if data["last_update"] > data.get("last_saved", 0):
                        # Calculate flow duration
                        flow_duration = data["flow_end_time"] - data["flow_start_time"]

                        # Calculate statistics
                        packet_sizes = list(data["packet_sizes"])
                        avg_packet_size = (
                            statistics.mean(packet_sizes) if packet_sizes else 0
                        )
                        payload_size_mean = (
                            statistics.mean(data["payload_sizes"])
                            if data["payload_sizes"]
                            else 0
                        )

                        # Calculate packet ratio
                        packet_ratio = data["bytes_up"] / max(1, data["bytes_down"])

                        # Calculate burstiness
                        if len(data["packet_size_list"]) > 1:
                            iat_sequence = [
                                data["packet_size_list"][i + 1]
                                - data["packet_size_list"][i]
                                for i in range(len(data["packet_size_list"]) - 1)
                            ]
                            iat_mean = (
                                statistics.mean(iat_sequence) if iat_sequence else 0
                            )
                            iat_std = (
                                statistics.stdev(iat_sequence)
                                if len(iat_sequence) > 1
                                else 0
                            )
                            burstiness = iat_std / iat_mean if iat_mean > 0 else 0
                        else:
                            iat_mean = 0
                            iat_std = 0
                            burstiness = 0

                        # Insert data into database
                        cursor.execute(
                            """
                            INSERT INTO network_traffic (
                                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                                protocol, packet_size, flow_duration, packets_to_server,
                                packets_from_server, total_bytes_sent, total_bytes_received,
                                packet_ratio, payload_size_mean, iat_mean, iat_std, burstiness,
                                server_name_indication, client_hello_fingerprint
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                            (
                                mac,
                                None,
                                data["ip"],
                                None,
                                None,
                                None,
                                None,
                                avg_packet_size,
                                flow_duration,
                                data["packets_up"],
                                data["packets_down"],
                                data["bytes_up"],
                                data["bytes_down"],
                                packet_ratio,
                                payload_size_mean,
                                iat_mean,
                                iat_std,
                                burstiness,
                                data["server_name_indication"],
                                data["client_hello_fingerprint"],
                            ),
                        )

                        # Update last saved time
                        data["last_saved"] = time.time()

                db_conn.commit()

            time.sleep(Config.DATA_SAVE_INTERVAL)
        except Exception as e:
            print(f"Error saving data: {str(e)}", file=sys.stderr)
            time.sleep(5)


def print_sample_data():
    """Print the first 5 rows of captured data to the console."""
    print("\n📊 Sample of captured network traffic data:")
    print("-" * 80)

    try:
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM network_traffic ORDER BY timestamp LIMIT 5")
        rows = cursor.fetchall()

        if not rows:
            print("No data captured yet.")
            return

        # Get column names
        cursor.execute("PRAGMA table_info(network_traffic)")
        columns = [column[1] for column in cursor.fetchall()]

        # Print header
        print(" | ".join(columns))
        print("-" * 80)

        # Print rows
        for row in rows:
            # Format the output to be more readable
            formatted_row = []
            for value in row:
                if value is None:
                    formatted_row.append("NULL")
                elif isinstance(value, float):
                    formatted_row.append(f"{value:.2f}")
                else:
                    formatted_row.append(str(value))
            print(" | ".join(formatted_row))

        print("-" * 80)
    except sqlite3.Error as e:
        print(f"Error retrieving sample data: {str(e)}", file=sys.stderr)


def cleanup():
    """Clean up resources before exiting."""
    global db_conn
    if db_conn:
        try:
            db_conn.close()
            print("Database connection closed.")
        except sqlite3.Error as e:
            print(f"Error closing database connection: {str(e)}", file=sys.stderr)


def main():
    """Main entry point."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Wireless Network Traffic Monitor")
    parser.add_argument("-i", "--interface", help="Wireless interface to monitor")
    parser.add_argument(
        "--ip-range",
        default=Config.IP_RANGE,
        help="IP range to monitor (e.g., 192.168.1.0/24)",
    )
    args = parser.parse_args()

    # Get wireless interfaces if not specified
    if not args.interface:
        interfaces = get_wireless_interfaces()
        if not interfaces:
            print("No wireless interfaces found. Please specify one with -i.")
            sys.exit(1)

        print("Available wireless interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")

        try:
            choice = int(input("Select interface (1-{}): ".format(len(interfaces)))) - 1
            if 0 <= choice < len(interfaces):
                interface = interfaces[choice]
            else:
                print("Invalid selection. Using first interface.")
                interface = interfaces[0]
        except (ValueError, IndexError):
            print("Invalid input. Using first interface.")
            interface = interfaces[0]
    else:
        interface = args.interface

    print(f"🚀 Starting Wireless Network Traffic Monitor on interface: {interface}")
    print(f"Monitoring IP range: {args.ip_range}")

    # Start threads
    sniffer_thread = threading.Thread(
        target=sniffer_thread_func, args=(interface,), daemon=True
    )
    channel_hopper_thread = threading.Thread(
        target=channel_hopper, args=(interface,), daemon=True
    )
    data_saver_thread = threading.Thread(target=data_saver_thread_func, daemon=True)

    sniffer_thread.start()
    channel_hopper_thread.start()
    data_saver_thread.start()

    time.sleep(2)  # Give threads time to initialize

    print("Monitoring started. Press Ctrl+C to stop.")

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor...")
        stop_event.set()
        sniffer_thread.join(timeout=5)
        channel_hopper_thread.join(timeout=5)
        data_saver_thread.join(timeout=5)
        # Add a small delay to ensure all data is saved
        time.sleep(2)
        print_sample_data()  # Print sample data before cleanup

        cleanup()
        print("Monitor stopped. Data saved to database.")


if __name__ == "__main__":
    main()
