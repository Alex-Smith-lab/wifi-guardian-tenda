# WiFi Guardian — Tenda Edition

A local-first Windows network monitor with a GitHub Pages dashboard.

## Files
- `index.html` — responsive dashboard (can be published with GitHub Pages)
- `agent.py` — Windows local scanner/API; requires Python and Flask
- `requirements.txt` — Python dependency

## Run on Windows
1. Install Python 3.10+.
2. Open Command Prompt in this folder.
3. Run `py -m pip install -r requirements.txt`
4. Run `py agent.py` and keep the window open.
5. Open `index.html` in Chrome/Edge. If the browser blocks requests from a `file://` page, run `py -m http.server 8000` in this folder and open `http://127.0.0.1:8000`.
6. Keep the agent and the local web server running while monitoring.

## Publish the dashboard on GitHub Pages
1. Create a repository such as `wifi-guardian-tenda`.
2. Upload `index.html` and enable Pages under Settings → Pages → Deploy from a branch → `main` / root.
3. Important: a GitHub-hosted page cannot directly scan your LAN. This page calls the agent at `127.0.0.1:8765`, which means the dashboard works on the same PC where the agent runs. If the browser blocks the request due to secure-page/local-network policies, use the local `http://127.0.0.1:8000` dashboard instead.

## Limitations
- ARP/ping discovery can miss sleeping devices, devices that ignore ping, and devices isolated by the router.
- A new MAC address is not proof of hacking; phones can randomize their MAC addresses.
- This agent does not read Tenda admin pages or detect failed Wi-Fi password attempts. Those alerts require router-specific logs/syslog support. Never put your Tenda admin password in this project or publish it to GitHub.
- The API binds to loopback only and should not be exposed to the internet.
- Router address `192.168.0.1` is configurable; the agent detects the active local gateway.

## Tenda logs
Sign in to your router locally and look for System Tools / System Log / Security Log or an equivalent menu. Menu names vary by model. If remote syslog is supported, a later version can listen for logs and parse authentication/security events.
