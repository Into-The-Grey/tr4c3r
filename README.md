# TR4C3R 🔍

<p align="center">
  <strong>Advanced OSINT Platform for Digital Investigations</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#portable-usb">Portable USB</a> •
  <a href="#usage">Usage</a> •
  <a href="#api">API</a> •
  <a href="#documentation">Docs</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg" alt="Platform"/>
</p>

---

**TR4C3R** is a modular, open-source OSINT (Open-Source Intelligence) platform for searching usernames, emails, names, and phone numbers across the public web, social media, and the dark web. Built with Python 3.11+, it provides asynchronous searches, correlation engines, network graph visualization, and a complete web dashboard.

## ✨ Features

### 🔎 Search Capabilities

- **Username Search** - Search across 500+ platforms (GitHub, Reddit, Twitter, Instagram, etc.)
- **Email Search** - HIBP breach checks, email validation, domain analysis
- **Phone Search** - Carrier lookup, location data, social media associations
- **Name Search** - People search across public records and social media
- **Social Media Search** - Deep platform-specific searches
- **Dark Web Search** - Tor hidden service monitoring (requires Tor)

### 📊 Analysis & Visualization

- **Interactive Graph Dashboard** - D3.js force-directed network visualization
- **Correlation Engine** - Automatic relationship discovery between entities
- **Deduplication** - Intelligent result merging and confidence scoring
- **Threat Intelligence** - Integration with VirusTotal, AbuseIPDB, Shodan, OTX

### 🔔 Automation & Alerts

- **Scheduled Searches** - Cron-based automated monitoring
- **Multi-Channel Notifications** - Email, Slack, Discord, Telegram, webhooks
- **Alert Rules** - Custom triggers based on search results
- **Batch Processing** - Bulk search with progress tracking

### 📄 Reporting & Export

- **PDF Reports** - Professional executive summaries
- **HTML Reports** - Interactive web-based reports
- **Excel Export** - XLSX with multiple sheets
- **STIX 2.1** - Threat intelligence standard format
- **MISP** - Threat sharing platform format
- **Maltego** - Graph analysis tool format

### 🔐 Security & Privacy

- **JWT Authentication** - Secure API access with refresh tokens
- **Two-Factor Auth** - TOTP-based 2FA support
- **Role-Based Access** - Admin, Analyst, Viewer, API roles
- **Audit Logging** - Complete activity tracking
- **Data Encryption** - AES-256 encryption at rest
- **Tor/VPN Detection** - OPSEC security advisor

### 🔌 Extensibility

- **Plugin System** - Custom search modules and integrations
- **REST API** - Full-featured FastAPI backend
- **Mobile API** - Optimized endpoints for mobile apps
- **Webhooks** - Real-time event notifications

## 🚀 Installation

### Prerequisites

- Python 3.11+
- pipenv (recommended) or pip

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/tr4c3r.git
cd tr4c3r

# Install dependencies
pipenv install --dev
pipenv shell

# Copy configuration
cp config/tr4c3r.yaml.example config/tr4c3r.yaml

# Run the CLI
python -m src.cli --help
```

### Docker Install

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access the web dashboard
open http://localhost:8000
```

## 💾 Portable USB

TR4C3R can run entirely from a USB drive with no installation required. Download pre-built portable packages or build your own:

### Download Pre-Built Packages

| Platform | Architecture | Download |
|----------|--------------|----------|
| Windows | x64 | [tr4c3r-windows-x64.zip](releases) |
| macOS | Intel | [tr4c3r-macos-x64.tar.gz](releases) |
| macOS | Apple Silicon | [tr4c3r-macos-arm64.tar.gz](releases) |
| Linux | x64 | [tr4c3r-linux-x64.tar.gz](releases) |

### Build Portable Package

```bash
# Build for current platform
./scripts/build-portable.sh

# Build for specific platform (requires cross-compilation tools)
./scripts/build-portable.sh --platform windows
./scripts/build-portable.sh --platform macos
./scripts/build-portable.sh --platform linux
```

### Running from USB

1. Extract the package to your USB drive
2. Run the launcher:
   - **Windows**: Double-click `tr4c3r.exe` or run `start.bat`
   - **macOS**: Run `./start.sh` or double-click `TR4C3R.app`
   - **Linux**: Run `./start.sh`

The portable version includes:

- Complete Python runtime (no installation needed)
- All dependencies pre-installed
- Bundled configuration
- Persistent data storage on the drive

## 📖 Usage

### Command Line Interface

```bash
# Search for a username
python -m src.cli username johndoe

# Search with fuzzy variants
python -m src.cli username johndoe --fuzzy

# Email breach check
python -m src.cli email user@example.com

# Phone number lookup
python -m src.cli phone "+1-555-123-4567"

# Full investigation (all modules)
python -m src.cli all johndoe

# Export results
python -m src.cli username johndoe --output results.json --format json
python -m src.cli username johndoe --output report.pdf --format pdf
```

### Web Dashboard

```bash
# Start the API server
python -m src.api.main

# Open in browser
open http://localhost:8000
```

### Scheduled Searches

```bash
# Add a scheduled search
python -m src.cli schedule add "username johndoe" --cron "0 */6 * * *"

# List scheduled searches
python -m src.cli schedule list

# Start the scheduler daemon
python -m src.cli schedule start
```

## 🔌 API

TR4C3R provides a full REST API for integration:

```bash
# Get API token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Search username
curl -X POST http://localhost:8000/api/v1/search/username \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"query": "johndoe", "fuzzy": true}'

# Get results
curl http://localhost:8000/api/v1/results/<search_id> \
  -H "Authorization: Bearer <token>"
```

See [API Documentation](docs/API.md) for complete reference.

## 📚 Documentation

- [API Reference](docs/API.md)
- [API Quickstart](docs/API_QUICKSTART.md)
- [Authentication Guide](docs/AUTHENTICATION.md)
- [Docker Deployment](docs/DOCKER.md)
- [Security Guidelines](docs/SECURITY_GUIDELINES_SUMMARY.md)
- [Ethics & Safety](docs/ETHICS_SAFETY_LEVELS.md)
- [Integration Guide](docs/INTEGRATIONS.md)

## 🏗️ Project Structure

```text
tr4c3r/
├── src/
│   ├── api/              # REST API (FastAPI)
│   ├── core/             # Core functionality
│   │   ├── batch_search.py
│   │   ├── cache.py
│   │   ├── config.py
│   │   ├── correlation.py
│   │   ├── graph_exporter.py
│   │   ├── notifications.py
│   │   ├── reports.py
│   │   ├── scheduler.py
│   │   └── tagging.py
│   ├── search/           # Search modules
│   ├── security/         # Auth, encryption, OPSEC
│   ├── storage/          # Database layer
│   ├── visualization/    # Dashboard & graphs
│   └── cli.py            # CLI entry point
├── tests/                # Test suite (800+ tests)
├── docs/                 # Documentation
├── config/               # Configuration templates
├── scripts/              # Build & deployment scripts
└── portable/             # Portable build output
```

## 🧪 Development

```bash
# Run tests
pipenv run pytest

# Run with coverage
pipenv run pytest --cov=src --cov-report=html

# Lint code
pipenv run flake8 src tests
pipenv run black src tests --check

# Type checking
pipenv run mypy src
```

## ⚠️ Ethical Use

TR4C3R is designed for legitimate OSINT investigations only. Users must:

- Comply with all applicable laws and regulations
- Respect privacy and terms of service of target platforms
- Use the tool responsibly and ethically
- Not use for harassment, stalking, or illegal activities

See [Ethics & Safety Guidelines](docs/ETHICS_SAFETY_LEVELS.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Graph visualization with [D3.js](https://d3js.org/) and [vis.js](https://visjs.org/)
- PDF generation with [ReportLab](https://www.reportlab.com/)
- Security powered by [cryptography](https://cryptography.io/)

---

<p align="center">
  Made with ❤️ for the OSINT community
</p>
