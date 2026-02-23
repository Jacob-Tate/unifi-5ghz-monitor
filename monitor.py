#!/usr/bin/env python3
"""
UniFi 5GHz Band Monitor
Detects APs with 0 clients on 5GHz but clients on 2.4GHz/6GHz bands
Supports .env configuration and webhook notifications (Pushover, Discord, etc.)
Updated for UniFi OS (New API) and Legacy compatibility
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
    def __init__(self, host: str, username: str, password: str, port: int = 443, verify_ssl: bool = False, verbose: bool = False, trace: bool = False, client_threshold: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}"
        self.network_prefix = "" # Will be set during login (/proxy/network for new API)
        
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.verbose = verbose
        self.trace = trace
        self.client_threshold = client_threshold
        
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
        
        if self.verbose:
            self.logger.info(f"Client threshold set to: {self.client_threshold} (APs with fewer clients will not trigger alerts)")
    
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
        
        if priority == "emergency":
            data["retry"] = 60
            data["expire"] = 3600
        
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
            "color": 16711680,
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
        """Login to UniFi Controller (Handles both new UniFi OS and Legacy)"""
        login_data = {
            "username": self.username,
            "password": self.password,
            "remember": True
        }
        
        try:
            # 1. Try modern UniFi OS login (UDM, CloudKey Gen2, modern self-hosted)
            response = self.session.post(
                f"{self.base_url}/api/auth/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.network_prefix = "/proxy/network"
                
                # UniFi OS requires X-CSRF-Token for subsequent requests
                csrf_token = response.headers.get("x-csrf-token")
                if csrf_token:
                    self.session.headers.update({"X-CSRF-Token": csrf_token})
                    
                self.logger.info("Successfully logged into UniFi OS Controller (New API)")
                return True
                
        except Exception as e:
            self.logger.debug(f"UniFi OS login attempt failed or timed out: {e}")

        try:
            # 2. Fallback to classic UniFi Controller login
            self.logger.debug("Attempting fallback to legacy UniFi Controller login...")
            response = self.session.post(
                f"{self.base_url}/api/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.network_prefix = ""
                self.logger.info("Successfully logged into Classic UniFi Controller (Legacy API)")
                return True
            else:
                self.logger.error(f"Both login methods failed. Status Code: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            return False
    
    def get_sites(self) -> List[Dict]:
        """Get all sites"""
        try:
            response = self.session.get(f"{self.base_url}{self.network_prefix}/api/self/sites")
            if response.status_code == 200:
                return response.json()['data']
            return []
        except Exception as e:
            self.logger.error(f"Error getting sites: {e}")
            return []
    
    def get_access_points(self, site_name: str = "default") -> List[Dict]:
        """Get all access points for a site"""
        try:
            response = self.session.get(f"{self.base_url}{self.network_prefix}/api/s/{site_name}/stat/device")
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
            response = self.session.get(f"{self.base_url}{self.network_prefix}/api/s/{site_name}/stat/sta")
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
        
        radio_table = ap.get('radio_table', [])
        
        if self.trace:
            self.logger.trace(f"  Raw radio_table data: {radio_table}")
        
        for radio in radio_table:
            radio_name = radio.get('name', '')
            radio_type = radio.get('radio', '')
            channel = radio.get('channel', 'N/A')
            tx_power = radio.get('tx_power', radio.get('max_txpower', 'N/A'))
            utilization = radio.get('satisfaction', 'N/A')
            
            radio_enabled = channel not in ['N/A', None, 0] and not radio.get('disabled', False)
            
            if self.trace:
                self.logger.trace(f"  Processing radio: {radio_name}, type: {radio_type}, enabled: {radio_enabled}, channel: {channel}")
            
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
        
        # Method 1: Check radio name patterns
        if any(pattern in radio for pattern in ['ng', '2g', 'radio_2g', 'radio-2g', 'wifi0']):
            return '2g'
        elif any(pattern in radio for pattern in ['6g', '6e', 'radio_6g', 'radio-6g', 'wifi2', 'ax6g']):
            return '6g'
        elif any(pattern in radio for pattern in ['na', '5g', 'radio_5g', 'radio-5g', 'wifi1']):
            return '5g'
        
        # Method 2: Check radio protocol
        if '6g' in radio_proto or 'be' in radio_proto:
            return '6g'
        elif '11ax-5g' in radio_proto or ('ax' in radio_proto and 'na' in radio):
            return '5g'
        elif '11ax-2g' in radio_proto or ('ax' in radio_proto and 'ng' in radio):
            return '2g'
        
        # Method 3: Enhanced channel-based detection
        if channel:
            if 1 <= channel <= 14:
                return '2g'
            elif channel in [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93] and channel <= 93:
                if 'na' in radio and channel >= 36:
                    return '5g'
                else:
                    return '6g'
            elif 36 <= channel <= 165:
                return '5g'
            elif channel >= 200:
                return '6g'
        
        # Method 4: Fallback
        tx_rate = client.get('tx_rate', 0)
        if isinstance(tx_rate, (int, float)) and tx_rate > 2000:
            return '6g'
        
        return None
    
    def analyze_ap_bands(self, site_name: str = "default") -> List[Dict]:
        """Analyze APs for 5GHz band issues with verbose details and client threshold filtering"""
        aps = self.get_access_points(site_name)
        clients = self.get_clients(site_name)
        
        if self.verbose:
            self.logger.info(f"Found {len(aps)} access points and {len(clients)} clients")
        
        problematic_aps = []
        skipped_low_count = []
        
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
            
            if ap_state != 1:
                continue
            
            radio_details = self.get_radio_details(ap)
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
                radio_proto = client.get('radio_proto', '')
                
                client_info = {
                    'hostname': hostname, 'mac': mac, 'rssi': rssi,
                    'tx_rate': tx_rate, 'rx_rate': rx_rate, 'uptime': uptime,
                    'channel': channel, 'radio': radio, 'radio_proto': radio_proto
                }
                
                band = self._detect_client_band(radio, channel, radio_proto, client)
                
                if band:
                    band_counts[band] += 1
                    client_details[band].append(client_info)
            
            total_clients = sum(band_counts.values())
            has_5g_issue = (band_counts['5g'] == 0 and (band_counts['2g'] > 0 or band_counts['6g'] > 0))
            meets_threshold = total_clients >= self.client_threshold
            
            if has_5g_issue and not meets_threshold:
                skipped_low_count.append({
                    'ap_name': ap_name, 'total_clients': total_clients,
                    'threshold': self.client_threshold, 'clients_2g': band_counts['2g'],
                    'clients_5g': band_counts['5g'], 'clients_6g': band_counts['6g']
                })
                has_5g_issue = False
            
            if (has_5g_issue and meets_threshold) or self.verbose:
                issue_data = {
                    'ap_name': ap_name, 'ap_mac': ap_mac, 'ap_model': ap_model,
                    'ap_version': ap_version, 'clients_2g': band_counts['2g'],
                    'clients_5g': band_counts['5g'], 'clients_6g': band_counts['6g'],
                    'total_clients': total_clients, 'meets_threshold': meets_threshold,
                    'timestamp': datetime.now().isoformat(), 'uptime': ap_uptime,
                    'radio_details': radio_details, 'client_details': client_details,
                    'has_issue': has_5g_issue and meets_threshold
                }
                
                if has_5g_issue and meets_threshold:
                    problematic_aps.append(issue_data)
                    self.logger.warning(
                        f"5GHz ISSUE DETECTED - AP: {ap_name} ({ap_model}) - "
                        f"2.4GHz: {band_counts['2g']} clients, 5GHz: {band_counts['5g']} clients, "
                        f"6GHz: {band_counts['6g']} clients (Total: {total_clients}, Threshold: {self.client_threshold})"
                    )
                elif self.verbose:
                    self.logger.info(f"✅ AP {ap_name} - No 5GHz issues detected (Total clients: {total_clients})")
        
        return problematic_aps
    
    def restart_ap_radios(self, ap_mac: str, site_name: str = "default") -> bool:
        """Restart AP radios (potential fix for 5GHz issues)"""
        try:
            restart_data = {
                "cmd": "restart",
                "mac": ap_mac
            }
            
            response = self.session.post(
                f"{self.base_url}{self.network_prefix}/api/s/{site_name}/cmd/devmgr",
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
          f"6GHz: {ap_info['clients_6g']} "
          f"(Total: {ap_info['total_clients']})")

def main():
    # Load configuration from environment variables
    CONTROLLER_HOST = os.getenv('UNIFI_HOST', '192.168.1.1')
    USERNAME = os.getenv('UNIFI_USERNAME', 'admin')
    PASSWORD = os.getenv('UNIFI_PASSWORD', 'password')
    PORT = int(os.getenv('UNIFI_PORT', '443')) # Note: default port for UniFi OS is 443 instead of 8443
    SITE_NAME = os.getenv('UNIFI_SITE', 'default')
    
    # Monitoring settings
    CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '300'))
    AUTO_RESTART = os.getenv('AUTO_RESTART', 'false').lower() == 'true'
    VERBOSE_MODE = os.getenv('VERBOSE_MODE', 'true').lower() == 'true'
    TRACE_MODE = os.getenv('TRACE_MODE', 'false').lower() == 'true'
    WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'false').lower() == 'true'
    CLIENT_THRESHOLD = int(os.getenv('CLIENT_THRESHOLD', '10'))
    
    print("UniFi 5GHz Band Monitor Starting...")
    print(f"Controller: {CONTROLLER_HOST}:{PORT}")
    print(f"Site: {SITE_NAME}")
    print(f"Check Interval: {CHECK_INTERVAL} seconds")
    print("-" * 50)
    
    controller = UniFiController(
        CONTROLLER_HOST, USERNAME, PASSWORD, PORT, 
        verbose=VERBOSE_MODE, trace=TRACE_MODE, client_threshold=CLIENT_THRESHOLD
    )
    
    if not controller.login():
        print("Failed to login to UniFi Controller. Exiting.")
        return
    
    consecutive_issues = {}
    
    try:
        while True:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[{timestamp}] Running 5GHz band check (threshold: {CLIENT_THRESHOLD} clients)...")
            
            problematic_aps = controller.analyze_ap_bands(SITE_NAME)
            
            if problematic_aps:
                print(f"\n⚠️  FOUND {len(problematic_aps)} APs WITH 5GHz ISSUES:")
                
                for i, ap_info in enumerate(problematic_aps, 1):
                    ap_mac = ap_info['ap_mac']
                    previous_count = consecutive_issues.get(ap_mac, 0)
                    consecutive_issues[ap_mac] = previous_count + 1
                    
                    print(f"\nISSUE #{i}:")
                    print_detailed_ap_info(ap_info, VERBOSE_MODE)
                    print(f"🔄 Consecutive issues: {consecutive_issues[ap_mac]}")
                    
                    if AUTO_RESTART and consecutive_issues[ap_mac] >= 3:
                        print(f"\n🔄 Auto-restarting AP {ap_info['ap_name']} after 3 consecutive issues...")
                        if controller.restart_ap_radios(ap_mac, SITE_NAME):
                            consecutive_issues[ap_mac] = 0
            else:
                print("✅ No 5GHz band issues detected (above threshold)")
                consecutive_issues.clear()
            
            print(f"\n⏰ Next check in {CHECK_INTERVAL} seconds...")
            time.sleep(CHECK_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Monitoring stopped by user")

if __name__ == "__main__":
    main()
