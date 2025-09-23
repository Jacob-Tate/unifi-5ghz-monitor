#!/usr/bin/env python3
"""
UniFi 5GHz Band Monitor
Detects APs with 0 clients on 5GHz but clients on 2.4GHz/6GHz bands
Supports .env configuration and webhook notifications (Pushover, Discord, etc.)
"""

import requests
import json
import time
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional
import urllib3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Suppress SSL warnings if using self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add custom TRACE logging level
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")

def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL):
        self._log(TRACE_LEVEL, message, args, **kwargs)

logging.Logger.trace = trace

class UniFiController:
    def __init__(self, host: str, username: str, password: str, port: int = 443, verify_ssl: bool = False, verbose: bool = False, trace: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.verbose = verbose
        self.trace = trace
        
        # Webhook configuration
        self.webhook_url = os.getenv('WEBHOOK_URL')
        self.webhook_type = os.getenv('WEBHOOK_TYPE', 'generic').lower()
        self.pushover_token = os.getenv('PUSHOVER_TOKEN')
        self.pushover_user = os.getenv('PUSHOVER_USER')
        self.discord_username = os.getenv('DISCORD_USERNAME', 'UniFi Monitor')
        
        # Setup logging with configurable file and levels
        log_file = os.getenv('LOG_FILE', 'unifi_5ghz_monitor.log')
        
        # Determine log level
        if trace:
            log_level = TRACE_LEVEL
        elif verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
            
        # Clear any existing handlers to avoid duplicates
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ],
            force=True  # Force reconfiguration
        )
        self.logger = logging.getLogger(__name__)
    
    def send_webhook_notification(self, title: str, message: str, priority: str = "normal") -> bool:
        """Send webhook notification with support for multiple platforms"""
        if not self.webhook_url:
            return False
        
        try:
            if self.webhook_type == 'pushover':
                return self._send_pushover(title, message, priority)
            elif self.webhook_type == 'discord':
                return self._send_discord(title, message)
            elif self.webhook_type == 'slack':
                return self._send_slack(title, message)
            else:
                return self._send_generic_webhook(title, message, priority)
                
        except Exception as e:
            self.logger.error(f"Webhook notification failed: {e}")
            return False
    
    def _send_pushover(self, title: str, message: str, priority: str = "normal") -> bool:
        """Send Pushover notification"""
        if not self.pushover_token or not self.pushover_user:
            self.logger.error("Pushover token or user not configured")
            return False
        
        priority_map = {"low": -1, "normal": 0, "high": 1, "emergency": 2}
        
        data = {
            "token": self.pushover_token,
            "user": self.pushover_user,
            "title": title,
            "message": message,
            "priority": priority_map.get(priority, 0)
        }
        
        # Add emergency priority settings
        if priority == "emergency":
            data["retry"] = 60  # Retry every 60 seconds
            data["expire"] = 3600  # Expire after 1 hour
        
        response = requests.post("https://api.pushover.net/1/messages.json", data=data, timeout=10)
        
        if response.status_code == 200:
            self.logger.info("Pushover notification sent successfully")
            return True
        else:
            self.logger.error(f"Pushover notification failed: {response.status_code} - {response.text}")
            return False
    
    def _send_discord(self, title: str, message: str) -> bool:
        """Send Discord webhook notification"""
        embed = {
            "title": title,
            "description": message,
            "color": 16711680,  # Red color for issues
            "timestamp": datetime.utcnow().isoformat()
        }
        
        data = {
            "username": self.discord_username,
            "embeds": [embed]
        }
        
        response = requests.post(self.webhook_url, json=data, timeout=10)
        
        if response.status_code == 204:
            self.logger.info("Discord notification sent successfully")
            return True
        else:
            self.logger.error(f"Discord notification failed: {response.status_code}")
            return False
    
    def _send_slack(self, title: str, message: str) -> bool:
        """Send Slack webhook notification"""
        data = {
            "text": f"*{title}*\n{message}",
            "username": "UniFi Monitor",
            "icon_emoji": ":warning:"
        }
        
        response = requests.post(self.webhook_url, json=data, timeout=10)
        
        if response.status_code == 200:
            self.logger.info("Slack notification sent successfully")
            return True
        else:
            self.logger.error(f"Slack notification failed: {response.status_code}")
            return False
    
    def _send_generic_webhook(self, title: str, message: str, priority: str = "normal") -> bool:
        """Send generic webhook notification"""
        data = {
            "title": title,
            "message": message,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat(),
            "service": "unifi_5ghz_monitor"
        }
        
        response = requests.post(self.webhook_url, json=data, timeout=10)
        
        if response.status_code in [200, 201, 202, 204]:
            self.logger.info("Generic webhook notification sent successfully")
            return True
        else:
            self.logger.error(f"Generic webhook notification failed: {response.status_code}")
            return False
    
    def login(self) -> bool:
        """Login to UniFi Controller"""
        try:
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            response = self.session.post(
                f"{self.base_url}/api/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Successfully logged into UniFi Controller")
                return True
            else:
                self.logger.error(f"Login failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            return False
    
    def get_sites(self) -> List[Dict]:
        """Get all sites"""
        try:
            response = self.session.get(f"{self.base_url}/api/self/sites")
            if response.status_code == 200:
                return response.json()['data']
            return []
        except Exception as e:
            self.logger.error(f"Error getting sites: {e}")
            return []
    
    def get_access_points(self, site_name: str = "default") -> List[Dict]:
        """Get all access points for a site"""
        try:
            response = self.session.get(f"{self.base_url}/api/s/{site_name}/stat/device")
            if response.status_code == 200:
                devices = response.json()['data']
                # Filter for access points only
                return [device for device in devices if device.get('type') == 'uap']
            return []
        except Exception as e:
            self.logger.error(f"Error getting access points: {e}")
            return []
    
    def get_clients(self, site_name: str = "default") -> List[Dict]:
        """Get all connected clients for a site"""
        try:
            response = self.session.get(f"{self.base_url}/api/s/{site_name}/stat/sta")
            if response.status_code == 200:
                return response.json()['data']
            return []
        except Exception as e:
            self.logger.error(f"Error getting clients: {e}")
            return []
    
    def get_radio_details(self, ap: Dict) -> Dict:
        """Extract detailed radio information from AP"""
        radio_details = {
            '2g': {'enabled': False, 'channel': None, 'power': None, 'utilization': None, 'interference': None},
            '5g': {'enabled': False, 'channel': None, 'power': None, 'utilization': None, 'interference': None},
            '6g': {'enabled': False, 'channel': None, 'power': None, 'utilization': None, 'interference': None}
        }
        
        # Parse radio table information
        radio_table = ap.get('radio_table', [])
        
        if self.trace:
            self.logger.trace(f"  Raw radio_table data: {radio_table}")
        
        for radio in radio_table:
            radio_name = radio.get('name', '')
            radio_type = radio.get('radio', '')  # This is the radio type (ng, na, 6e)
            channel = radio.get('channel', 'N/A')
            tx_power = radio.get('tx_power', radio.get('max_txpower', 'N/A'))
            utilization = radio.get('satisfaction', 'N/A')
            
            # Radio is considered enabled if it has a valid channel (not 'auto' or disabled state)
            # UniFi shows 'auto' for enabled radios on auto channel selection
            radio_enabled = channel not in ['N/A', None, 0] and not radio.get('disabled', False)
            
            if self.trace:
                self.logger.trace(f"  Processing radio: {radio_name}, type: {radio_type}, enabled: {radio_enabled}, channel: {channel}")
            
            # Enhanced radio detection based on radio type
            if radio_type == 'ng' or 'ng' in radio_name.lower() or '2g' in radio_name.lower() or radio_name.lower() == 'wifi0':
                radio_details['2g'] = {
                    'enabled': radio_enabled,
                    'channel': channel if radio_enabled else 'N/A',
                    'power': tx_power,
                    'utilization': utilization,
                    'interference': radio.get('interference', 'N/A')
                }
            elif radio_type == 'na' or 'na' in radio_name.lower() or '5g' in radio_name.lower() or radio_name.lower() == 'wifi1':
                radio_details['5g'] = {
                    'enabled': radio_enabled,
                    'channel': channel if radio_enabled else 'N/A',
                    'power': tx_power,
                    'utilization': utilization,
                    'interference': radio.get('interference', 'N/A')
                }
            elif radio_type == '6e' or '6e' in radio_name.lower() or '6g' in radio_name.lower() or radio_name.lower() == 'wifi2':
                radio_details['6g'] = {
                    'enabled': radio_enabled,
                    'channel': channel if radio_enabled else 'N/A',
                    'power': tx_power,
                    'utilization': utilization,
                    'interference': radio.get('interference', 'N/A')
                }
        
        return radio_details
    
    def _detect_client_band(self, radio: str, channel: int, radio_proto: str, client: Dict) -> Optional[str]:
        """Improved band detection logic"""
        radio = radio.lower()
        radio_proto = radio_proto.lower()
        
        if self.trace:
            self.logger.trace(f"    Band detection: radio='{radio}', channel={channel}, proto='{radio_proto}'")
        
        # Method 1: Check radio name patterns (most reliable)
        if any(pattern in radio for pattern in ['ng', '2g', 'radio_2g', 'radio-2g', 'wifi0']):
            if self.trace:
                self.logger.trace(f"    -> 2G (radio pattern match)")
            return '2g'
        elif any(pattern in radio for pattern in ['6g', '6e', 'radio_6g', 'radio-6g', 'wifi2', 'ax6g']):
            if self.trace:
                self.logger.trace(f"    -> 6G (radio pattern match)")
            return '6g'
        elif any(pattern in radio for pattern in ['na', '5g', 'radio_5g', 'radio-5g', 'wifi1']):
            if self.trace:
                self.logger.trace(f"    -> 5G (radio pattern match)")
            return '5g'
        
        # Method 2: Check radio protocol
        if '6g' in radio_proto or 'be' in radio_proto:  # WiFi 7 (802.11be) is primarily 6GHz
            if self.trace:
                self.logger.trace(f"    -> 6G (protocol match)")
            return '6g'
        elif '11ax-5g' in radio_proto or ('ax' in radio_proto and 'na' in radio):
            if self.trace:
                self.logger.trace(f"    -> 5G (protocol match)")
            return '5g'
        elif '11ax-2g' in radio_proto or ('ax' in radio_proto and 'ng' in radio):
            if self.trace:
                self.logger.trace(f"    -> 2G (protocol match)")
            return '2g'
        
        # Method 3: Enhanced channel-based detection
        if channel:
            # 2.4GHz channels (1-14)
            if 1 <= channel <= 14:
                if self.trace:
                    self.logger.trace(f"    -> 2G (channel range)")
                return '2g'
            
            # 6GHz channels - these are the actual 6GHz channel numbers used by UniFi
            # Common 6GHz channels: 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93
            elif channel in [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93] and channel <= 93:
                # Additional check: if we're already confident this is 5GHz from other factors, keep it as 5GHz
                if 'na' in radio and channel >= 36:
                    if self.trace:
                        self.logger.trace(f"    -> 5G (na radio with high channel)")
                    return '5g'
                # Otherwise, if channel is in typical 6GHz range, it's probably 6GHz
                else:
                    if self.trace:
                        self.logger.trace(f"    -> 6G (6GHz channel range)")
                    return '6g'
            
            # Traditional 5GHz channels
            elif 36 <= channel <= 165:
                if self.trace:
                    self.logger.trace(f"    -> 5G (5GHz channel range)")
                return '5g'
            
            # High 6GHz channels (200+) - some deployments use these
            elif channel >= 200:
                if self.trace:
                    self.logger.trace(f"    -> 6G (high 6GHz channel)")
                return '6g'
        
        # Method 4: Fallback - look at tx_rate patterns (6GHz typically has higher rates)
        tx_rate = client.get('tx_rate', 0)
        if isinstance(tx_rate, (int, float)) and tx_rate > 2000:  # Very high rates suggest 6GHz
            if self.trace:
                self.logger.trace(f"    -> 6G (high tx_rate: {tx_rate})")
            return '6g'
        
        # If all else fails, return None
        if self.trace:
            self.logger.trace(f"    -> UNKNOWN (no match found)")
        return None
    
    def analyze_ap_bands(self, site_name: str = "default") -> List[Dict]:
        """Analyze APs for 5GHz band issues with verbose details"""
        aps = self.get_access_points(site_name)
        clients = self.get_clients(site_name)
        
        if self.verbose:
            self.logger.info(f"Found {len(aps)} access points and {len(clients)} clients")
        
        problematic_aps = []
        
        for ap in aps:
            ap_mac = ap.get('mac', '')
            ap_name = ap.get('name', ap_mac)
            ap_model = ap.get('model', 'Unknown')
            ap_state = ap.get('state', 0)
            ap_uptime = ap.get('uptime', 0)
            ap_version = ap.get('version', 'Unknown')
            
            if self.verbose:
                self.logger.debug(f"\n{'='*60}")
                self.logger.debug(f"ANALYZING AP: {ap_name} ({ap_model})")
                self.logger.debug(f"MAC: {ap_mac}")
                self.logger.debug(f"State: {'Online' if ap_state == 1 else 'Offline'}")
                self.logger.debug(f"Uptime: {ap_uptime // 3600}h {(ap_uptime % 3600) // 60}m")
                self.logger.debug(f"Firmware: {ap_version}")
            
            if ap_state != 1:  # Skip offline APs
                if self.verbose:
                    self.logger.debug(f"SKIPPING - AP {ap_name} is offline")
                continue
            
            # Get detailed radio information
            radio_details = self.get_radio_details(ap)
            
            if self.verbose:
                self.logger.debug("RADIO STATUS:")
                for band, details in radio_details.items():
                    if details['enabled']:
                        self.logger.debug(f"  {band.upper()}: CH {details['channel']}, "
                                        f"Power {details['power']}dBm, "
                                        f"Util {details['utilization']}%")
                    else:
                        self.logger.debug(f"  {band.upper()}: DISABLED")
            
            # Count clients by band for this AP
            ap_clients = [client for client in clients if client.get('ap_mac') == ap_mac]
            
            band_counts = {'2g': 0, '5g': 0, '6g': 0}
            client_details = {'2g': [], '5g': [], '6g': []}
            
            for i, client in enumerate(ap_clients):
                radio = client.get('radio', '')
                channel = client.get('channel', 0)
                hostname = client.get('hostname', client.get('name', 'Unknown'))
                mac = client.get('mac', 'Unknown')
                rssi = client.get('rssi', 'N/A')
                tx_rate = client.get('tx_rate', 'N/A')
                rx_rate = client.get('rx_rate', 'N/A')
                uptime = client.get('uptime', 0)
                
                # Additional fields that might help with band detection
                radio_proto = client.get('radio_proto', '')
                essid = client.get('essid', '')
                
                client_info = {
                    'hostname': hostname,
                    'mac': mac,
                    'rssi': rssi,
                    'tx_rate': tx_rate,
                    'rx_rate': rx_rate,
                    'uptime': uptime,
                    'channel': channel,
                    'radio': radio,
                    'radio_proto': radio_proto
                }
                
                if self.verbose:
                    self.logger.debug(f"  Client: {hostname}, Radio: {radio}, Channel: {channel}, Proto: {radio_proto}")
                
                # Full client data dump for trace level only
                if self.trace and i <= 2:
                    self.logger.trace(f"    Full client data: {json.dumps(client, indent=2)}")
                
                # Enhanced band detection logic
                band = self._detect_client_band(radio, channel, radio_proto, client)
                
                if band:
                    band_counts[band] += 1
                    client_details[band].append(client_info)
                elif self.verbose:
                    self.logger.debug(f"    Could not determine band for client {hostname} - Radio: {radio}, Channel: {channel}")
            
            if self.verbose:
                self.logger.debug("CLIENT DISTRIBUTION:")
                for band in ['2g', '5g', '6g']:
                    self.logger.debug(f"  {band.upper()}: {band_counts[band]} clients")
                    if client_details[band]:
                        for client in client_details[band]:
                            self.logger.debug(f"    - {client['hostname']} (RSSI: {client['rssi']}dBm, "
                                            f"CH: {client['channel']}, Up: {client['uptime']//60}m)")
            
            # Check for the specific issue: 0 clients on 5GHz but clients on other bands
            has_5g_issue = (band_counts['5g'] == 0 and (band_counts['2g'] > 0 or band_counts['6g'] > 0))
            
            if has_5g_issue or self.verbose:
                issue_data = {
                    'ap_name': ap_name,
                    'ap_mac': ap_mac,
                    'ap_model': ap_model,
                    'ap_version': ap_version,
                    'clients_2g': band_counts['2g'],
                    'clients_5g': band_counts['5g'],
                    'clients_6g': band_counts['6g'],
                    'total_clients': sum(band_counts.values()),
                    'timestamp': datetime.now().isoformat(),
                    'uptime': ap_uptime,
                    'radio_details': radio_details,
                    'client_details': client_details,
                    'has_issue': has_5g_issue
                }
                
                if has_5g_issue:
                    problematic_aps.append(issue_data)
                    
                    self.logger.warning(
                        f"5GHz ISSUE DETECTED - AP: {ap_name} ({ap_model}) - "
                        f"2.4GHz: {band_counts['2g']} clients, "
                        f"5GHz: {band_counts['5g']} clients, "
                        f"6GHz: {band_counts['6g']} clients"
                    )
                    
                    if self.verbose:
                        # Additional diagnostic information for problematic APs
                        if radio_details['5g']['enabled']:
                            self.logger.warning(f"  5GHz Radio: CH {radio_details['5g']['channel']}, "
                                              f"Power {radio_details['5g']['power']}dBm")
                            if radio_details['5g']['channel'] == 'N/A':
                                self.logger.error("  ❌ 5GHz channel shows N/A - radio may be malfunctioning")
                        else:
                            self.logger.error("  ❌ 5GHz radio appears to be DISABLED")
                
                elif self.verbose:
                    self.logger.info(f"✅ AP {ap_name} - No 5GHz issues detected")
        
        return problematic_aps
    
    def restart_ap_radios(self, ap_mac: str, site_name: str = "default") -> bool:
        """Restart AP radios (potential fix for 5GHz issues)"""
        try:
            restart_data = {
                "cmd": "restart",
                "mac": ap_mac
            }
            
            response = self.session.post(
                f"{self.base_url}/api/s/{site_name}/cmd/devmgr",
                json=restart_data
            )
            
            if response.status_code == 200:
                self.logger.info(f"Restart command sent to AP {ap_mac}")
                return True
            else:
                self.logger.error(f"Failed to restart AP {ap_mac}: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restarting AP {ap_mac}: {e}")
            return False

def print_detailed_ap_info(ap_info: Dict, verbose: bool = False):
    """Print detailed information about an AP"""
    print(f"AP Name: {ap_info['ap_name']}")
    print(f"Model: {ap_info['ap_model']}")
    print(f"MAC: {ap_info['ap_mac']}")
    print(f"Firmware: {ap_info.get('ap_version', 'Unknown')}")
    print(f"Uptime: {ap_info['uptime'] // 3600}h {(ap_info['uptime'] % 3600) // 60}m")
    
    print(f"Clients - 2.4GHz: {ap_info['clients_2g']}, "
          f"5GHz: {ap_info['clients_5g']}, "
          f"6GHz: {ap_info['clients_6g']}")
    
    if verbose and 'radio_details' in ap_info:
        print("\nRadio Status:")
        for band, details in ap_info['radio_details'].items():
            if details['enabled']:
                print(f"  {band.upper()}: Channel {details['channel']}, "
                      f"Power {details['power']}dBm, "
                      f"Utilization {details['utilization']}%")
                if details['interference'] != 'N/A':
                    print(f"    Interference: {details['interference']}")
            else:
                print(f"  {band.upper()}: ❌ DISABLED")
    
    if verbose and 'client_details' in ap_info:
        print("\nConnected Clients:")
        for band in ['2g', '5g', '6g']:
            clients = ap_info['client_details'][band]
            if clients:
                print(f"  {band.upper()} Band ({len(clients)} clients):")
                for client in clients:
                    print(f"    • {client['hostname']} ({client['mac']})")
                    print(f"      RSSI: {client['rssi']}dBm, "
                          f"TX: {client['tx_rate']}Mbps, "
                          f"RX: {client['rx_rate']}Mbps")
                    print(f"      Channel: {client['channel']}, "
                          f"Connected: {client['uptime']//60}m")

def main():
    # Load configuration from environment variables
    CONTROLLER_HOST = os.getenv('UNIFI_HOST', '192.168.1.1')
    USERNAME = os.getenv('UNIFI_USERNAME', 'admin')
    PASSWORD = os.getenv('UNIFI_PASSWORD', 'password')
    PORT = int(os.getenv('UNIFI_PORT', '443'))
    SITE_NAME = os.getenv('UNIFI_SITE', 'default')
    
    # Monitoring settings
    CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '300'))  # 5 minutes default
    AUTO_RESTART = os.getenv('AUTO_RESTART', 'false').lower() == 'true'
    VERBOSE_MODE = os.getenv('VERBOSE_MODE', 'true').lower() == 'true'
    TRACE_MODE = os.getenv('TRACE_MODE', 'false').lower() == 'true'  # New trace mode
    WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'false').lower() == 'true'
    
    print("UniFi 5GHz Band Monitor Starting...")
    print(f"Controller: {CONTROLLER_HOST}:{PORT}")
    print(f"Site: {SITE_NAME}")
    print(f"Check Interval: {CHECK_INTERVAL} seconds")
    print(f"Auto-restart APs: {AUTO_RESTART}")
    print(f"Verbose Mode: {VERBOSE_MODE}")
    print(f"Trace Mode: {TRACE_MODE}")
    print(f"Webhook Notifications: {WEBHOOK_ENABLED}")
    print(f"Log File: {os.getenv('LOG_FILE', 'unifi_5ghz_monitor.log')}")
    print("-" * 50)
    
    controller = UniFiController(CONTROLLER_HOST, USERNAME, PASSWORD, PORT, verbose=VERBOSE_MODE, trace=TRACE_MODE)
    
    if not controller.login():
        print("Failed to login to UniFi Controller. Exiting.")
        if WEBHOOK_ENABLED:
            controller.send_webhook_notification(
                "UniFi Monitor - Login Failed",
                f"Failed to login to UniFi Controller at {CONTROLLER_HOST}:{PORT}",
                "high"
            )
        return
    
    # Send startup notification
    if WEBHOOK_ENABLED:
        controller.send_webhook_notification(
            "UniFi Monitor - Started",
            f"5GHz band monitoring started for {CONTROLLER_HOST}\nCheck interval: {CHECK_INTERVAL}s\nLogging: {'TRACE' if TRACE_MODE else 'DEBUG' if VERBOSE_MODE else 'INFO'}",
            "normal"
        )
    
    consecutive_issues = {}  # Track consecutive issues per AP
    
    try:
        while True:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            mode_str = 'TRACE ' if TRACE_MODE else 'VERBOSE ' if VERBOSE_MODE else ''
            print(f"\n[{timestamp}] Running {mode_str}5GHz band check...")
            
            if VERBOSE_MODE or TRACE_MODE:
                print("🔍 Gathering detailed AP and client information...")
            
            problematic_aps = controller.analyze_ap_bands(SITE_NAME)
            
            if problematic_aps:
                print(f"\n⚠️  FOUND {len(problematic_aps)} APs WITH 5GHz ISSUES:")
                print("=" * 80)
                
                # Prepare webhook message
                webhook_message_parts = []
                
                for i, ap_info in enumerate(problematic_aps, 1):
                    print(f"\nISSUE #{i}:")
                    print_detailed_ap_info(ap_info, VERBOSE_MODE or TRACE_MODE)
                    
                    ap_mac = ap_info['ap_mac']
                    previous_count = consecutive_issues.get(ap_mac, 0)
                    consecutive_issues[ap_mac] = previous_count + 1
                    
                    print(f"\n🔄 Consecutive issues: {consecutive_issues[ap_mac]}")
                    
                    # Add to webhook message
                    webhook_message_parts.append(
                        f"AP: {ap_info['ap_name']} ({ap_info['ap_model']})\n"
                        f"2.4GHz: {ap_info['clients_2g']} clients, "
                        f"5GHz: {ap_info['clients_5g']} clients, "
                        f"6GHz: {ap_info['clients_6g']} clients\n"
                        f"Consecutive issues: {consecutive_issues[ap_mac]}"
                    )
                    
                    # Diagnostic suggestions
                    if VERBOSE_MODE or TRACE_MODE:
                        print("\n🩺 Diagnostic Analysis:")
                        radio_5g = ap_info.get('radio_details', {}).get('5g', {})
                        if not radio_5g.get('enabled'):
                            print("   ❌ 5GHz radio is disabled - check AP configuration")
                        elif radio_5g.get('channel') == 'N/A':
                            print("   ❌ 5GHz channel is N/A - possible radio malfunction")
                        elif radio_5g.get('power', 0) < 10:
                            print("   ⚠️  5GHz power is very low - may affect coverage")
                        else:
                            print("   ℹ️  5GHz radio appears configured correctly")
                            print("   💡 Possible causes: interference, firmware bug, hardware issue")
                    
                    # Auto-restart logic
                    if AUTO_RESTART and consecutive_issues[ap_mac] >= 3:
                        print(f"\n🔄 Auto-restarting AP {ap_info['ap_name']} after 3 consecutive issues...")
                        if controller.restart_ap_radios(ap_mac, SITE_NAME):
                            consecutive_issues[ap_mac] = 0  # Reset counter after restart
                            
                            # Send restart notification
                            if WEBHOOK_ENABLED:
                                controller.send_webhook_notification(
                                    "UniFi AP Auto-Restarted",
                                    f"AP {ap_info['ap_name']} ({ap_info['ap_model']}) has been automatically restarted due to persistent 5GHz issues.\n\nLocation: {CONTROLLER_HOST}\nReason: 5GHz band had 0 clients while other bands were active",
                                    "high"
                                )
                    
                    print("-" * 60)
                
                # Send webhook notification for issues (only for new issues or every 3rd consecutive issue)
                if WEBHOOK_ENABLED:
                    new_issues = [ap for ap in problematic_aps if consecutive_issues[ap['ap_mac']] == 1]
                    persistent_issues = [ap for ap in problematic_aps if consecutive_issues[ap['ap_mac']] % 3 == 0 and consecutive_issues[ap['ap_mac']] > 1]
                    
                    if new_issues:
                        title = f"UniFi 5GHz Issues Detected ({len(new_issues)} new)"
                        message = f"New 5GHz band issues detected on {CONTROLLER_HOST}:\n\n" + "\n\n".join([
                            f"• {ap['ap_name']} ({ap['ap_model']}): "
                            f"2.4GHz: {ap['clients_2g']}, 5GHz: {ap['clients_5g']}, 6GHz: {ap['clients_6g']}"
                            for ap in new_issues
                        ])
                        controller.send_webhook_notification(title, message, "high")
                    
                    elif persistent_issues:
                        title = f"UniFi Persistent 5GHz Issues ({len(persistent_issues)} APs)"
                        message = f"Persistent 5GHz issues on {CONTROLLER_HOST}:\n\n" + "\n\n".join([
                            f"• {ap['ap_name']}: {consecutive_issues[ap['ap_mac']]} consecutive checks"
                            for ap in persistent_issues
                        ])
                        controller.send_webhook_notification(title, message, "normal")
                
            else:
                print("✅ No 5GHz band issues detected")
                if VERBOSE_MODE or TRACE_MODE:
                    # Get all APs for summary even when no issues
                    all_aps = controller.get_access_points(SITE_NAME)
                    online_aps = [ap for ap in all_aps if ap.get('state') == 1]
                    print(f"📊 Summary: {len(online_aps)} APs online, all 5GHz bands functioning normally")
                
                # Send resolution notification if we had issues before
                if consecutive_issues and WEBHOOK_ENABLED:
                    controller.send_webhook_notification(
                        "UniFi 5GHz Issues Resolved",
                        f"All 5GHz band issues have been resolved on {CONTROLLER_HOST}.\nAll APs are now functioning normally.",
                        "normal"
                    )
                
                consecutive_issues.clear()  # Reset all counters when no issues
            
            print(f"\n⏰ Next check in {CHECK_INTERVAL} seconds...")
            if not VERBOSE_MODE and not TRACE_MODE:
                print("   💡 Tip: Set VERBOSE_MODE=true or TRACE_MODE=true in .env for detailed diagnostics")
            elif VERBOSE_MODE and not TRACE_MODE:
                print("   🔍 Tip: Set TRACE_MODE=true in .env for ultra-detailed API debugging")
            
            time.sleep(CHECK_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped by user")
        if WEBHOOK_ENABLED:
            controller.send_webhook_notification(
                "UniFi Monitor - Stopped",
                f"5GHz band monitoring stopped by user on {CONTROLLER_HOST}",
                "normal"
            )
    except Exception as e:
        controller.logger.error(f"Monitoring error: {e}")
        if VERBOSE_MODE or TRACE_MODE:
            import traceback
            controller.logger.error(f"Full traceback: {traceback.format_exc()}")
        
        if WEBHOOK_ENABLED:
            controller.send_webhook_notification(
                "UniFi Monitor - Error",
                f"Monitoring error on {CONTROLLER_HOST}: {str(e)}",
                "high"
            )

if __name__ == "__main__":
    main()
