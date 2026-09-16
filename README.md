# NetShield Home

NetShield Home is a self-hosted network security and parental-control dashboard for home and small-office networks.

It brings network monitoring, device management, traffic controls, Wi-Fi security checks, and basic security analysis into one web application that runs locally on your own machine.

No cloud service or external database is required. Data is stored locally using SQLite.

## Features

### Network & Device Monitoring

* Discover devices connected to the local network
* View IP address, MAC address, and vendor information
* Detect randomized/private MAC addresses
* Resolve device hostnames where possible
* Organize devices into groups such as Kids, Guests, IoT, and Trusted
* View devices through a simple network topology
* Monitor device bandwidth usage

### Traffic & Parental Controls

* Temporarily cut a device's network access
* Apply bandwidth limits
* Block selected domain categories
* Create scheduled rules such as bedtime restrictions
* Restore network access when a restriction is removed
* View the current status of traffic-control rules

These controls are intended for networks that you own or are authorized to manage.

### DNS History

NetShield Home can record DNS requests that are visible to the machine running the application.

The dashboard provides:

* Domain history
* Top domains
* Filtering and searching
* Per-device history where traffic is visible
* Daily, weekly, and monthly views
* CSV export
* Optional domain categorization

NetShield does **not** decrypt HTTPS traffic. It does not use a fake certificate authority or inspect the contents of encrypted websites.

### Security Dashboard

The security section provides basic network security checks, including:

* TCP port scanning
* Risk scoring for detected ports
* Static vulnerability information
* Security recommendations
* Threat-intelligence information
* Remediation suggestions

The vulnerability information is advisory only. NetShield Home does not attempt to exploit vulnerabilities.

### Wi-Fi Security

Depending on the operating system and available tools, NetShield Home can inspect nearby wireless networks and identify issues such as:

* Open networks
* WEP networks
* Possible evil-twin situations
* Channel congestion

It also includes a basic RF channel recommendation system for 2.4 GHz and 5 GHz networks.

### Alerts & Reports

The application can generate alerts for events such as:

* New devices joining the network
* High-risk ports
* Wireless security issues
* Data-usage thresholds

It also supports:

* Live dashboard notifications
* CSV reports
* Optional PDF reports
* Administrative activity logs

### Realtime Dashboard

Socket.IO is used to update the web interface without requiring constant page refreshes.

For example, the dashboard can receive updates when:

* A device joins or leaves
* An alert is created
* A traffic-control state changes
* A scan finishes

---

## Safety

NetShield Home is designed for use on networks that you own or are authorized to administer.

Network-control and scanning operations are restricted to the configured local network and exclude important addresses such as the gateway and the host machine itself.

The application also checks its network configuration and available privileges before enabling features that require low-level network access.

**Do not use NetShield Home to monitor, scan, or interfere with networks you do not have permission to manage.**

---

## Requirements

* Python 3.11 or newer
* Windows, Linux, or macOS

Some features require additional system privileges or networking tools.

### Windows

Windows users may need [Npcap](https://npcap.com/) for packet-capture features.

Features that interact directly with network traffic may also require running the application with Administrator privileges.

### Linux

Some networking features require root privileges.

Wi-Fi scanning may also require NetworkManager and `nmcli`.

### macOS

Some low-level networking features require elevated privileges and may have platform-specific limitations.

If required networking capabilities are unavailable, NetShield Home falls back to the features that can still operate normally.

---

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd netshield-home
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**Linux/macOS**

```bash
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Initialize the database:

```bash
python create_db.py
```

Then start the application:

```bash
python run.py
```

Open the address shown by the application in your browser.

---

## Configuration

NetShield Home can be configured using environment variables.

| Variable            | Description                              |
| ------------------- | ---------------------------------------- |
| `NETSHIELD_HOST`    | Address the web application listens on   |
| `NETSHIELD_PORT`    | Port used by the web application         |
| `NETSHIELD_SUBNET`  | Optional local subnet override           |
| `NETSHIELD_GATEWAY` | Optional gateway override                |
| `NETSHIELD_DEBUG`   | Enables Flask debug mode when set to `1` |

For example:

```bash
NETSHIELD_PORT=5000
```

Avoid committing environment files containing passwords, API keys, tokens, or other private configuration.

---

## Project Structure

```text
netshield-home/
├── run.py
├── create_db.py
├── config.py
├── requirements.txt
├── data/
└── netshield/
    ├── __init__.py
    ├── extensions.py
    ├── safety.py
    ├── security.py
    ├── audit.py
    ├── models/
    ├── services/
    ├── blueprints/
    ├── templates/
    └── static/
```

### Main components

* `services/` — network discovery, scanning, DNS, Wi-Fi, traffic control, reporting, and other application services
* `blueprints/` — Flask routes and web application modules
* `models/` — database models
* `templates/` — web interface
* `static/` — CSS and JavaScript
* `safety.py` — shared network-safety checks
* `security.py` — authentication and authorization
* `audit.py` — administrative activity logging

---

## Data & Privacy

NetShield Home is designed around local storage.

Network information and application data are stored locally in the application's data directory.

The project does not require a cloud database or hosted backend.

Keep the `data/` directory out of version control if it contains:

* Database files
* Session secrets
* Generated credentials
* Private network information
* Other runtime data

A `.gitignore` file should therefore include entries similar to:

```gitignore
data/
venv/
__pycache__/
*.pyc
.env
```

If you need to keep example configuration files in the repository, use placeholder values rather than real credentials or tokens.

---

## Troubleshooting

### Network features are unavailable

Some features require Administrator/root privileges or packet-capture support.

Check that:

* The required networking software is installed
* The application is running with the necessary privileges
* Your operating system supports the requested feature

### Wi-Fi scanning is unavailable

Wi-Fi scanning depends on the operating system and installed networking tools.

Windows uses the system wireless tools, while Linux installations may use NetworkManager.

### DNS history is empty

DNS visibility depends on where NetShield Home is running on the network.

A computer connected to the same network does not necessarily see every DNS request made by other devices. Some routers and access points handle client traffic internally.

---

## Limitations

NetShield Home is intended as a home/small-office network management and security tool rather than a replacement for enterprise security infrastructure.

In particular:

* It does not decrypt HTTPS traffic.
* It does not exploit vulnerabilities.
* Network visibility depends on the network topology and operating system.
* Some low-level networking features require elevated privileges.
* Wi-Fi capabilities vary between operating systems and hardware.
* DNS history only contains queries that NetShield can actually observe.

---

## License

Add the project's license here once one has been selected.

For example:

```text
MIT License
```

---

## Disclaimer

NetShield Home is provided for network administration, security learning, and authorized testing.

Only use the application on networks and devices that you own or have explicit permission to manage.
