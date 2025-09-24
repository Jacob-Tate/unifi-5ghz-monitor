# UniFi 5GHz Band Monitor

A comprehensive monitoring tool that detects and alerts on UniFi Access Point 5GHz band issues. This monitor identifies APs where the 5GHz radio has no connected clients while 2.4GHz or 6GHz bands are actively serving clients - a common symptom of firmware bugs or hardware issues.

## 🚨 Problem It Solves

UniFi APs sometimes experience a bug where the 5GHz radio becomes unavailable to clients while appearing "enabled" in the controller. Clients can still connect to 2.4GHz and 6GHz bands, but avoid the 5GHz band entirely. This results in:
- Reduced network performance (clients stuck on slower 2.4GHz)
- Poor user experience in 5GHz-dependent applications
- Difficult to detect without manual monitoring

## ✨ Features

- **🎯 Smart Detection**: Identifies APs with 5GHz client distribution issues
- **📊 Client Threshold**: Prevents false positives on lightly-used APs (configurable minimum client count)
- **🔄 Auto-Restart**: Optionally restart problematic APs automatically
- **📱 Multi-Platform Webhooks**: Pushover, Discord, Slack, and generic webhook support
- **📝 Comprehensive Logging**: Three logging levels (INFO/DEBUG/TRACE) with rotation
- **⚙️ Service Integration**: Includes systemd service and logrotate configuration
- **🔍 Detailed Diagnostics**: Radio status, client details, and troubleshooting info

## 📋 Requirements

- Python 3.6+
- UniFi Network Controller (Cloud Key, Dream Machine, or self-hosted)
- Network access to UniFi Controller
- Required Python packages: `requests`, `python-dotenv`

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip3 install requests python-dotenv
```

### 2. Clone and Configure
```bash
git clone <your-repo>
cd unifi-5ghz-monitor
cp .env.example .env
```

### 3. Edit Configuration
```bash
nano .env
```

**Essential settings:**
```bash
# UniFi Controller
UNIFI_HOST=192.168.1.1
UNIFI_USERNAME=your_username
UNIFI_PASSWORD=your_password
UNIFI_PORT=8443

# Alert Threshold (NEW!)
CLIENT_THRESHOLD=10  # Only alert if AP has 10+ total clients

# Webhook notifications
WEBHOOK_ENABLED=true
WEBHOOK_TYPE=pushover  # or discord, slack, generic
```

### 4. Test Run
```bash
python3 monitor.py
```

## ⚙️ Configuration Options

### Core Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `UNIFI_HOST` | `192.168.1.1` | UniFi Controller IP address |
| `UNIFI_USERNAME` | `admin` | Controller username |
| `UNIFI_PASSWORD` | `password` | Controller password |
| `UNIFI_PORT` | `8443` | Controller port (8443 for new, 443 for legacy) |
| `UNIFI_SITE` | `default` | Site name in controller |

### Monitoring Behavior
| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_INTERVAL` | `300` | Seconds between checks (5 minutes) |
| `CLIENT_THRESHOLD` | `10` | **Minimum total clients before alerting** |
| `AUTO_RESTART` | `false` | Auto-restart APs after 3 consecutive issues |
| `VERBOSE_MODE` | `false` | Enable detailed logging |
| `TRACE_MODE` | `false` | Enable ultra-detailed API debugging |

### Webhook Configuration
| Variable | Description |
|----------|-------------|
| `WEBHOOK_ENABLED` | `true/false` - Enable notifications |
| `WEBHOOK_TYPE` | `pushover`, `discord`, `slack`, or `generic` |
| `WEBHOOK_URL` | Webhook endpoint URL |

#### Pushover Setup
```bash
WEBHOOK_TYPE=pushover
WEBHOOK_URL=https://api.pushover.net/1/messages.json
PUSHOVER_TOKEN=your_app_token
PUSHOVER_USER=your_user_key
```

#### Discord Setup
```bash
WEBHOOK_TYPE=discord
WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook/url
DISCORD_USERNAME=UniFi Monitor
```

#### Slack Setup
```bash
WEBHOOK_TYPE=slack
WEBHOOK_URL=https://hooks.slack.com/services/your/slack/webhook
```

## 🎯 Client Threshold Feature

**NEW in this version!** The `CLIENT_THRESHOLD` setting prevents false positives on lightly-used APs.

### How It Works
- Monitor only alerts if an AP has **≥ threshold total clients** AND has 5GHz issues
- APs below threshold are logged but don't trigger alerts
- Default threshold: 10 clients

### Example Scenarios
```bash
CLIENT_THRESHOLD=10

# WILL NOT ALERT (below threshold)
AP-Office: 3 clients (2.4GHz: 3, 5GHz: 0, 6GHz: 0) ✅ SKIPPED

# WILL ALERT (above threshold + 5GHz issue)  
AP-Lobby: 15 clients (2.4GHz: 12, 5GHz: 0, 6GHz: 3) ⚠️ ALERT

# WILL NOT ALERT (above threshold but no 5GHz issue)
AP-Conference: 20 clients (2.4GHz: 8, 5GHz: 7, 6GHz: 5) ✅ OK
```

### Recommended Thresholds
- **Home network**: 3-5 clients
- **Small office**: 8-12 clients  
- **Large office**: 15-25 clients
- **High-density**: 25+ clients

## 📊 Usage Examples

### Basic Monitoring
```bash
# Run once for testing
python3 monitor.py

# Run with detailed output
VERBOSE_MODE=true python3 monitor.py
```

### Sample Output
```
UniFi 5GHz Band Monitor Starting...
Controller: 192.168.1.10:8443
Client Threshold: 10 (APs with fewer clients will not trigger alerts)
Check Interval: 300 seconds
─────────────────────────────

[2024-12-28 10:30:00] Running 5GHz band check (threshold: 10 clients)...
📊 Skipped 2 APs due to low client count (< 10)
✅ No 5GHz band issues detected (above threshold)
📊 Summary: 12 APs online, all 5GHz bands functioning normally
⏰ Next check in 300 seconds...
```

### When Issues Are Found
```
⚠️  FOUND 1 APS WITH 5GHz ISSUES (above threshold):
═══════════════════════════════════════════

ISSUE #1:
AP Name: AP-MainFloor
Model: U6-Enterprise
Clients - 2.4GHz: 18, 5GHz: 0, 6GHz: 4 (Total: 22)
🔄 Consecutive issues: 1

🩺 Diagnostic Analysis:
   ℹ️  5GHz radio appears configured correctly
   💡 Possible causes: interference, firmware bug, hardware issue
```

## 🔧 Installation as Service

### 1. Create User and Setup
```bash
sudo useradd -r -s /bin/false unifi_user
sudo mkdir -p /home/unifi_user
sudo cp monitor.py .env /home/unifi_user/
sudo chown -R unifi_user:unifi_user /home/unifi_user
```

### 2. Install Service
```bash
sudo cp unifi-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable unifi-monitor
sudo systemctl start unifi-monitor
```

### 3. Setup Log Rotation
```bash
sudo cp unifi-monitor /etc/logrotate.d/
```

### 4. Monitor Service
```bash
# Check status
sudo systemctl status unifi-monitor

# View logs
sudo journalctl -u unifi-monitor -f

# View application logs
tail -f /var/log/unifi_monitor.log
```

## 🔍 Troubleshooting

### Common Issues

**Login Failed**
- Verify UniFi controller IP, port, username, and password
- Check if using correct port (8443 for new UniFi OS, 443 for legacy)
- Ensure network connectivity to controller

**No APs Found**
- Verify site name (usually "default")
- Check if APs are online in controller
- Confirm user has admin/read access to site

**False Positives**
- Increase `CLIENT_THRESHOLD` value
- Check if 5GHz is intentionally disabled on specific APs
- Review client connection patterns during different times

**Missing Webhook Notifications**
- Test webhook URL manually
- Verify webhook tokens/credentials
- Check firewall rules for outbound connections

### Debug Mode
Enable detailed logging to diagnose issues:
```bash
# In .env file
VERBOSE_MODE=true
TRACE_MODE=true  # For ultimate detail
```

### Band Detection Issues
The monitor uses multiple methods to detect client bands:
1. Radio name patterns (most reliable)
2. Radio protocol detection  
3. Channel number ranges
4. TX rate analysis

If clients are being misclassified, enable `TRACE_MODE=true` to see detailed band detection logic.

## 📝 Logging

### Log Levels
- **INFO**: Basic status and issues
- **DEBUG** (`VERBOSE_MODE=true`): Detailed AP analysis
- **TRACE** (`TRACE_MODE=true`): Complete API data dumps

### Log Rotation
The included logrotate configuration:
- Rotates when log reaches 100MB
- Keeps 7 rotated files
- Compresses old logs
- Creates timestamped filenames

## 🤝 Contributing

This tool can easily be extended for other UniFi monitoring tasks:
- Channel utilization alerts
- Interference detection  
- Client roaming analysis
- Firmware update notifications
- Performance monitoring

## 📜 License

This project is provided as-is for network administrators managing UniFi deployments. Use responsibly and ensure you have proper authorization to monitor your network infrastructure.

---

**💡 Pro Tip**: Start with `CLIENT_THRESHOLD=5` and adjust based on your environment's normal client distribution patterns.
