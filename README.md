🛡️ ThreatIntel Pro
A Comprehensive SOC & OSINT Automation Platform

ThreatIntel Pro is a high-performance, modular security operations dashboard designed for automated reconnaissance, vulnerability assessment, and threat analysis. Built with a focus on anonymity and scalability, it integrates global threat intelligence feeds with local sandbox capabilities.

🚀 Key Features
🌐 Intelligence & OSINT
IP Intelligence: Deep scanning using Nmap and reputation checks via AbuseIPDB and Shodan Academic API.

Site & Domain Analysis: Complete DNS mapping (A, MX, NS, TXT/SPF), TLS certificate validation, and infrastructure health monitoring.

Tor-Proxied OSINT: Anonymous directory brute-forcing and sensitive file discovery (e.g., .env, .git) routed through the Tor network to prevent IP blacklisting.

🔬 Sandbox & Malware Analysis
File Malware Scanner: Static analysis using python-magic for MIME-type validation and global reputation lookups via VirusTotal (MD5/SHA-256 hashes).

URL Reputation & Traffic: Real-time URL analysis using Google Safe Browsing and redirect chain tracking via Tor.

🤖 Automation & Monitoring
Scheduled Scans: Automated background tasks powered by APScheduler for continuous target monitoring.

Drift Analysis: Intelligent comparison between scans to detect infrastructure changes, such as newly opened ports or modified services.

Geospatial Visualization: Interactive world map plotting of threat origins and target locations.

🛠️ Tech StackLayerTechnologiesBackendPython 3.10+, FastAPI, SQLModel (ORM)FrontendReact, Material UI (MUI), RechartsDatabasePostgreSQL (JSONB for complex scan data storage)InfrastructureDocker & Docker Compose, Tor ProxySecurity APIsShodan, VirusTotal, AbuseIPDB, Google Safe Browsing

🏗️ Architecture
The project follows a Service-Oriented Architecture (SOA):

FastAPI Routers: Modularized endpoints for Analysis, History, and Monitoring.

PostgreSQL JSONB: Optimized storage for nested scan results, allowing complex queries directly on vulnerability data.

Async Workers: Non-blocking Nmap and API executions using Python's asyncio.

📦 Installation & Setup
Clone the repository:

Bash
git clone https://github.com/GabeRoot/threatintel-pro.git
cd threatintel-pro
Configure Environment Variables:
Create a .env file in the root directory:

Snippet de código
   SHODAN_API_KEY=your_key
   ABUSEIPDB_API_KEY=your_key
   VIRUSTOTAL_API_KEY=your_key
   DATABASE_URL=postgresql://user:pass@db:5432/threat_db
Run with Docker Compose:

Bash
   docker-compose up --build
🛡️ Educational Purpose
This project was developed by Gabriel, an Information Security student, for academic and professional portfolio purposes. It demonstrates the integration of modern backend architectures with cybersecurity best practices.
