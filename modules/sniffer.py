"""
module_sniffer.py
-----------------
This module implements a network sniffer using Scapy. It captures packets on a specified
interface, logs external IP addresses along with the destination port they attempt to connect to,
and publishes each captured event via MQTT to a single broker. Each published message is formatted as:

    sensor_id|base64(raw packet)

The module loads its configuration from a JSON file (if present) or uses defaults.
It supports interactive configuration—including an option to add extra filter ranges—and commands for
one-time (foreground) sniffing or continuous background sniffing. It requires root privileges.

The default configuration can be modified to produce your expected results or the main user 
interactive menu can be used to produce the configuration and save it to disk for future ease of use.

"""

from registry import application, menu_registry
import os, json, logging, threading, time, datetime, ipaddress, uuid, base64
import paho.mqtt.client as mqtt
from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw
import psutil

# Configure logging to output to console.
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

CONFIG_FILE = "sniffer_config.json"
DEFAULT_CONFIG = {
    "interface": "eth0",
    "monitor_local": False,
    "local_subnet": "192.168.1.0/24",
    "broker": "localhost",
    "port": 1883,
    "topic": "sniffer/data",
    "cafile": "",
    "certfile": "",
    "keyfile": "",
    "sensor_id": "",
    "extra_filter_ranges": []
}

# Default filter ranges (always filtered out)
DEFAULT_FILTER_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"), 
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4")
]

class Sniffer:
    def __init__(self):
        if os.geteuid() != 0:
            raise PermissionError("Sniffer module must be run as root.")
        self.interface = DEFAULT_CONFIG["interface"]
        self.monitor_local = DEFAULT_CONFIG["monitor_local"]
        self.local_subnet = DEFAULT_CONFIG["local_subnet"]
        self.broker = DEFAULT_CONFIG["broker"]
        self.port = DEFAULT_CONFIG["port"]
        self.topic = DEFAULT_CONFIG["topic"]
        self.cafile = DEFAULT_CONFIG["cafile"]
        self.certfile = DEFAULT_CONFIG["certfile"]
        self.keyfile = DEFAULT_CONFIG["keyfile"]
        self.sensor_id = DEFAULT_CONFIG["sensor_id"]
        self.extra_filter_ranges = []  # Will be a list of ipaddress.ip_network objects.
        self.mqtt_client = None
        self.connected = False
        self.sniff_thread = None
        self.stop_event = threading.Event()
        self.detection_logs = {}  # {"IP:PORT": {"last_detected": ..., "count": ...}}
        self.filter_established = True  # Ephemeral; resets each run.
        self.load_config()
        # Generate sensor_id if not set.
        if not self.sensor_id:
            self.sensor_id = str(uuid.uuid4())
            logger.info("Generated new sensor_id: %s", self.sensor_id)
            self.save_config()
        logger.debug("Configuration in use: interface=%s, monitor_local=%s, local_subnet=%s, broker=%s, port=%s, topic=%s, sensor_id=%s",
                     self.interface, self.monitor_local, self.local_subnet, self.broker, self.port, self.topic, self.sensor_id)
        # Build filter_subnets list from defaults + extra.
        self.filter_subnets = DEFAULT_FILTER_SUBNETS.copy()
        self.filter_subnets.extend(self.extra_filter_ranges)
        self.setup_mqtt()

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            logger.info("MQTT on_connect: Connected successfully")
        else:
            self.connected = False
            logger.error("MQTT on_connect: Connection failed with code %s", rc)

    def on_disconnect(self, client, userdata, rc):
        self.connected = False
        logger.warning("MQTT on_disconnect: Disconnected (rc=%s)", rc)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                self.interface = data.get("interface", self.interface)
                self.monitor_local = data.get("monitor_local", self.monitor_local)
                self.local_subnet = data.get("local_subnet", self.local_subnet)
                self.broker = data.get("broker", self.broker)
                self.port = int(data.get("port", self.port))
                self.topic = data.get("topic", self.topic)
                self.cafile = data.get("cafile", self.cafile)
                self.certfile = data.get("certfile", self.certfile)
                self.keyfile = data.get("keyfile", self.keyfile)
                self.sensor_id = data.get("sensor_id", self.sensor_id)
                extra = data.get("extra_filter_ranges", [])
                # Convert extra_filter_ranges to ip_network objects.
                self.extra_filter_ranges = []
                for net_str in extra:
                    try:
                        self.extra_filter_ranges.append(ipaddress.ip_network(net_str))
                    except Exception as e:
                        logger.error("Invalid extra filter range '%s': %s", net_str, e)
                logger.info("Loaded configuration from %s", CONFIG_FILE)
            except Exception as e:
                logger.error("Failed to load configuration: %s", e)
        else:
            logger.info("Configuration file not found; using defaults.")

    def save_config(self):
        data = {
            "interface": self.interface,
            "monitor_local": self.monitor_local,
            "local_subnet": self.local_subnet,
            "broker": self.broker,
            "port": self.port,
            "topic": self.topic,
            "cafile": self.cafile,
            "certfile": self.certfile,
            "keyfile": self.keyfile,
            "sensor_id": self.sensor_id,
            # Save extra filter ranges as list of strings.
            "extra_filter_ranges": [str(net) for net in self.extra_filter_ranges]
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(data, f, indent=4)
            logger.info("Configuration saved to %s", CONFIG_FILE)
        except Exception as e:
            logger.error("Failed to save configuration: %s", e)

    def get_listening_ports(self):
        ports = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    ports.add(conn.laddr.port)
        except Exception as e:
            logger.error("Error retrieving listening ports: %s", e)
        logger.debug("Listening ports: %s", ports)
        return ports

    def setup_mqtt(self):
        logger.debug("Attempting MQTT connection with broker=%s, port=%s", self.broker, self.port)
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_disconnect = self.on_disconnect
        try:
            if self.cafile and self.certfile and self.keyfile:
                self.mqtt_client.tls_set(ca_certs=self.cafile,
                                         certfile=self.certfile,
                                         keyfile=self.keyfile)
                logger.debug("TLS configured: cafile=%s, certfile=%s, keyfile=%s", self.cafile, self.certfile, self.keyfile)
            self.mqtt_client.connect(self.broker, int(self.port), 60)
            self.mqtt_client.loop_start()
            for _ in range(10):
                if self.connected:
                    break
                time.sleep(0.5)
            if not self.connected:
                logger.error("MQTT client failed to connect within timeout")
            else:
                logger.info("MQTT connected to %s:%s", self.broker, self.port)
                print("MQTT connected to", self.broker, "on port", self.port)
            return f"Connected to MQTT broker {self.broker}:{self.port}"
        except Exception as e:
            logger.error("MQTT connection failed: %s", e)
            return f"MQTT connection failed: {e}"

    def is_local(self, ip):
        if self.monitor_local:
            return False
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(self.local_subnet, strict=False)
        except Exception as e:
            logger.error("Error checking local subnet: %s", e)
            return False

    def process_packet(self, packet):
        # Determine if packet is IPv4 or IPv6 and get the source IP.
        src_ip = None
        if IP in packet:
            src_ip = packet[IP].src
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
        else:
            return  # Not an IP packet.

        # Check against default and extra filter ranges.
        if any(ipaddress.ip_address(src_ip) in net for net in (DEFAULT_FILTER_SUBNETS + self.extra_filter_ranges)):
            logger.debug("Skipping filtered IP: %s", src_ip)
            return

        # Optional: skip local addresses if monitoring local is disabled.
        if self.is_local(src_ip):
            logger.debug("Skipping local IP: %s", src_ip)
            return

        # Determine destination port if applicable.
        dst_port = None
        if TCP in packet:
            dst_port = packet[TCP].dport
            if self.filter_established:
                listening_ports = self.get_listening_ports()
                if dst_port in listening_ports:
                    flags = packet[TCP].flags
                    if flags & 0x10 and not flags & 0x02:
                        logger.debug("Skipping established session to port %s from %s", dst_port, src_ip)
                        return
        elif UDP in packet:
            dst_port = packet[UDP].dport

        key = f"{src_ip}:{dst_port}" if dst_port else src_ip
        now = datetime.datetime.now().isoformat()
        record = self.detection_logs.get(key, {"last_detected": now, "count": 0})
        record["last_detected"] = now
        record["count"] += 1
        self.detection_logs[key] = record

        # Instead of parsing out a TCP payload, send the entire raw packet.
        try:
            packet_bytes = bytes(packet)
            encoded_packet = base64.b64encode(packet_bytes).decode("utf-8")
        except Exception as e:
            logger.debug("Failed to encode packet: %s", e)
            encoded_packet = "NULL"

        # Build the MQTT message with the complete raw packet.
        payload_fields = [self.sensor_id, key, record["last_detected"], encoded_packet]
        raw_payload = "|".join(payload_fields)

        if self.mqtt_client is None or not self.connected:
            logger.debug("MQTT not connected; attempting to reconnect")
            self.setup_mqtt()
        result = self.mqtt_client.publish(self.topic, raw_payload)
        logger.info("Published suspected intruder packet: %s with result: %s", raw_payload, result)
        print("MQTT Publish:", raw_payload, "Result:", result)

    def _sniff(self):
        sniff(iface=self.interface, prn=self.process_packet, store=False,
              stop_filter=lambda pkt: self.stop_event.is_set())

    def execute_foreground(self, duration=30):
        self.detection_logs = {}
        logger.info("Starting one-time sniff for %s seconds on interface %s", duration, self.interface)
        sniff(iface=self.interface, prn=self.process_packet, store=False, timeout=duration)
        summary = ["Sniff Summary:"]
        for key, rec in self.detection_logs.items():
            summary.append(f"{key}|{rec['last_detected']}|{rec['count']}")
        return "\n".join(summary)

    def execute_background(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return "Background sniffer is already running."
        self.detection_logs.clear()
        self.stop_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff, daemon=True)
        self.sniff_thread.start()
        return "Background sniffer started."

    def stop_background_execution(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.stop_event.set()
            self.sniff_thread.join()
            self.sniff_thread = None
            return "Background sniffer stopped."
        else:
            return "Background sniffer is not running."

    def sniffer_status(self):
        if not self.detection_logs:
            return "No detections yet."
        summary = ["Current Sniffer Status:"]
        for key, rec in self.detection_logs.items():
            summary.append(f"{key}|{rec['last_detected']}|{rec['count']}")
        return "\n".join(summary)

    def interactive_configure(self):
        print("\n--- Sniffer Configuration ---")
        interface = input(f"Enter interface [current: {self.interface}]: ").strip() or self.interface
        monitor_local_in = input(f"Monitor local addresses? (y/n) [current: {'y' if self.monitor_local else 'n'}]: ").strip().lower()
        monitor_local = True if monitor_local_in == "y" else False
        local_subnet = input(f"Enter local subnet (CIDR) [current: {self.local_subnet}]: ").strip() or self.local_subnet
        broker = input(f"Enter MQTT broker [current: {self.broker}]: ").strip() or self.broker
        port_input = input(f"Enter MQTT port [current: {self.port}]: ").strip() or str(self.port)
        try:
            port = int(port_input)
        except ValueError:
            port = self.port
        topic = input(f"Enter MQTT topic [current: {self.topic}]: ").strip() or self.topic
        cafile = input(f"Enter CA certificate path [current: {self.cafile}]: ").strip() or self.cafile
        certfile = input(f"Enter client certificate path [current: {self.certfile}]: ").strip() or self.certfile
        keyfile = input(f"Enter client key path [current: {self.keyfile}]: ").strip() or self.keyfile

        self.interface = interface
        self.monitor_local = monitor_local
        self.local_subnet = local_subnet
        self.broker = broker
        self.port = port
        self.topic = topic
        self.cafile = cafile
        self.certfile = certfile
        self.keyfile = keyfile

        # Ask user if they want to add extra filter ranges.
        extra = input("Would you like to add extra filter ranges? (y/n) [default: n]: ").strip().lower()
        if extra == "y":
            ranges_str = input("Enter extra filter ranges as comma-separated CIDRs (e.g., 192.168.100.0/24, 10.10.0.0/16): ").strip()
            if ranges_str:
                range_list = [rng.strip() for rng in ranges_str.split(",") if rng.strip()]
                new_extra = []
                for rng in range_list:
                    try:
                        new_extra.append(ipaddress.ip_network(rng))
                    except Exception as e:
                        logger.error("Invalid CIDR '%s': %s", rng, e)
                self.extra_filter_ranges = new_extra
            else:
                self.extra_filter_ranges = []
        # Update filter_subnets (defaults + extra).
        self.filter_subnets = DEFAULT_FILTER_SUBNETS.copy()
        self.filter_subnets.extend(self.extra_filter_ranges)

        self.save_config()
        ssh_filter = input("Filter established sessions on listening services? (y/n) [default: y]: ").strip().lower()
        self.filter_established = False if ssh_filter == "n" else True
        return (f"Configuration updated: interface={self.interface}, monitor_local={self.monitor_local}, "
                f"local_subnet={self.local_subnet}, broker={self.broker}, port={self.port}, topic={self.topic}, "
                f"cafile={self.cafile}, certfile={self.certfile}, keyfile={self.keyfile}, "
                f"extra_filter_ranges={[str(net) for net in self.extra_filter_ranges]}, "
                f"filter_established={'enabled' if self.filter_established else 'disabled'}")

    def show_help(self):
        return (
            "\n=== Sniffer Help ===\n"
            "This module captures packets on a specified interface, logs external IP addresses along with\n"
            "the destination port that the remote machine is attempting to connect to, and publishes records via MQTT\n"
            "in the format:\n"
            "   sensor_id|IP:PORT|last_detected|<optional_tcp_payload>\n\n"
            "If a TCP payload is present, it is base64 encoded; otherwise, 'NULL' is used.\n\n"
            "Available commands:\n"
            "  config    : Enter interactive configuration mode.\n"
            "  execute   : Run a one-time sniffing session for 30 seconds and display a summary.\n"
            "  background: Start continuous background sniffing.\n"
            "  stop      : Stop background sniffing.\n"
            "  status    : Display current detection logs from the background process.\n"
            "  help (h)  : Display this help message.\n"
            "  back      : Return to the main menu.\n"
            "\nTip: This module requires root privileges.\n"
            "================================\n"
        )

    def control(self, command):
        while True:
            cmd = command.strip().lower()
            if cmd in ["help", "h"]:
                print(self.show_help())
                command = input("Enter command (or 'back' to return): ")
                continue
            elif cmd == "back":
                return "Returning to menu."
            elif cmd == "config":
                print("\n" + "="*60)
                print("Sniffer Interactive Configuration")
                print("Example (defaults shown):")
                print("  interface: eth0")
                print("  monitor_local: n")
                print("  local_subnet: 192.168.1.0/24")
                print("  broker: localhost")
                print("  port: 1883")
                print("  topic: sniffer/data")
                print("  cafile: (if using TLS)")
                print("  certfile: (if using TLS)")
                print("  keyfile: (if using TLS)")
                print("  extra_filter_ranges: (e.g., 192.168.100.0/24, 10.10.0.0/16)")
                print("="*60)
                result = self.interactive_configure()
                return result
            elif cmd == "execute":
                return self.execute_foreground()
            elif cmd == "background":
                return self.execute_background()
            elif cmd == "stop":
                return self.stop_background_execution()
            elif cmd == "status":
                return self.sniffer_status()
            elif cmd == "":
                return self.execute_foreground()
            else:
                print("Invalid command. Use 'help', 'config', 'execute', 'background', 'stop', 'status', or 'back'.")
                command = input("Enter command: ")
                continue

# Create and register the Sniffer instance.
sniffer_instance = Sniffer()
application["sniffer_instance"] = sniffer_instance
logger.info("Registered Sniffer instance under key 'sniffer_instance'")

# Register the module's menu metadata.
menu_registry.append({
    "category": ["Security", "Sniffer", "Network"],
    "name": "Sniffer",
    "help": "Configure ('config') and run the sniffer. Options: 'help', 'config', 'execute', 'background', 'stop', 'status', 'back'.",
    "callback": lambda target: sniffer_instance.control(target)
})
logger.info("Registered sniffer module under Security > Sniffer > Network")
