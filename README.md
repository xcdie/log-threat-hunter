#  log-threat-hunter

A lightweight, signature-based signature-matching Security Information and Event Management engine built in Python. It parses live application server logs asynchronously via file system hook abstractions to capture attacks mid-transit.

##  Detection Matrix Capabilities
The tool features real-time Regular Expression (Regex) filters designed to map strings against common security threats:
- **SQL Injection (SQLi):** Catches nested statement unions and logical escape strings.
- **Local File Inclusion (LFI):** Intercepts standard directory system path traversals (`../../`).
- **Cross-Site Scripting (XSS):** Identifies script injection vectors and payload script signatures.

##  Quick Setup & Test
1. Clone the project locally:
   ```bash
   git clone https://github.com/xcdie/log-threat-hunter.git
   cd log-threat-hunter
   ```
2. Spin up the security observer engine:
   ```bash
   python3 hunter.py
   ```
3. Test the detection accuracy in a separate terminal tab by injecting a mock threat string:
   ```bash
   echo "127.0.0.1 - - GET /index.php?id=1 UNION SELECT null, username FROM users" >> app_production.log
   ```

##  Architecture Roadmap
- [ ] Connect logs natively to standard system aggregators (`/var/log/nginx/access.log`).
- [ ] Incorporate IP Geolocation lookup tags for foreign connection requests.
- [ ] Build out a real-time WebSocket dashboard visualization UI.
