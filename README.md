# SSL/TLS Renegotiation DoS — Step-by-Step Walkthrough

---

## Safety reminder

This document is intended **only** for teaching and defensive testing in an isolated lab under your control. Do **not** run offensive tools or tests on third-party systems or any network you do not own/explicitly control. Where the original text referenced offensive tooling, those references are preserved *only as citations* and must be treated with strict institutional policy and legal oversight.

---

## 1 — Summary / Key recommendations

* **Attack vector:** TLS/SSL *renegotiation* (presentation layer / OSI Layer 6). Repeated client-initiated renegotiations can be CPU-intensive and can lead to server degradation (DoS).
* **Primary mitigations:**

  1. **Upgrade to TLS 1.3** — TLS 1.3 removes protocol renegotiation.
  2. **Disable client-initiated renegotiation** in server settings if available.
  3. **Rate-limit handshakes / connection renegotiations** and use reverse proxies/WAFs to offload crypto.

---

## 2 — Lab topology (demo addresses)

Use an isolated lab network (host-only or private VLAN). Example IPs used in this guide:

* **Attacker / Test VM (Kali)**: `192.168.1.2`
* **Victim TLS Server VM (Ubuntu)**: `192.168.1.3`
* **Observer / Validation VM (Wireshark / logging)**: `192.168.1.4`

---

## 3 — Observability / Wireshark filters

Start packet capture on the observer or attacker VM to illustrate traffic patterns.

Recommended Wireshark filter approach (conceptual filters to reduce noise):

* Exclude link-local and discovery traffic:
  `!arp && !ssdp && !browser && !igmp && !icmpv6 && !mdns`
* Focus on victim traffic:
  `ip.addr == 192.168.1.3`
* To inspect TLS/TCP payloads (example):
  `ip.addr == 192.168.1.3 && tcp.port == 8080`
  *(Adjust ports/IPs to match your lab.)*

---

## 4 — Attacker / Test VM notes (Kali)

> **Note:** You should **not** run offensive tools on networks you do not control. Use these references strictly in a controlled lab and only if your institutional rules permit.

* Example scanning/renegotiation check using `sslyze` (informational):
  `sslyze --reneg 192.168.1.3:8080`

* Example (original repo reference) — historic tool: `thc-tls-dos` (github: `azet/thc-tls-dos`) — **do not run outside isolated lab**. Original usage in source material:
  `./thc-ssl-dos --accept -l 1 192.168.1.3 8080`
  *(Preserved only as documentation/reference of historical tools; follow legal/ethical guidance before use.)*

---

## 5 — Victim VM (Ubuntu) — Step-by-step TLS server setup

Create a simple TLS-enabled HTTP server to demonstrate normal handshakes and to let students observe handshake CPU cost. Use Python for a minimal example.

### 5.1 Create a sample site

```bash
# on Ubuntu victim (192.168.1.3)
mkdir -p ~/sslserver
cd ~/sslserver

# simple index.html
cat > index.html <<'HTML'
<html>
  <body>
    <h1>This will be served on Ubuntu 192.168.1.3</h1>
  </body>
</html>
HTML
```

### 5.2 Create a self-signed certificate (lab only)

```bash
# Generate a self-signed cert and key (lab-only)
openssl req -x509 -newkey rsa:2048 \
  -keyout mykey.key -out mycert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Lab/CN=192.168.1.3"
```

You can verify the public key if desired:

```bash
openssl x509 -pubkey -noout -in mycert.pem
```

### 5.3 Minimal Python HTTPS server (corrected)

Create a file `server.py` with the following content (Python 3):

```python
# server.py
import http.server
import ssl
import socketserver

HOST = '0.0.0.0'
PORT = 8080
CERT_FILE = 'mycert.pem'
KEY_FILE = 'mykey.key'

class Handler(http.server.SimpleHTTPRequestHandler):
    pass

if __name__ == '__main__':
    httpd = socketserver.TCPServer((HOST, PORT), Handler)

    # Recommended: use SSLContext to explicitly set TLS versions
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # For the remediation step we will enforce TLS 1.3 where supported:
    # context.minimum_version = ssl.TLSVersion.TLSv1_3
    # context.maximum_version = ssl.TLSVersion.TLSv1_3

    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"Serving HTTPS on {HOST}:{PORT}")
    httpd.serve_forever()
```

**Notes:**

* The `ssl.SSLContext` approach is preferable over `ssl.wrap_socket` because it allows explicit control of TLS versions and options.
* To **enforce TLS 1.3** (if your Python/OpenSSL supports it), uncomment and use `context.minimum_version = ssl.TLSVersion.TLSv1_3`. If your Python/OpenSSL does not support TLS 1.3, set `minimum_version` appropriately (e.g., `TLSv1_2`) and upgrade OpenSSL/Python on the VM for TLS 1.3 support.

### 5.4 Run the server

```bash
# inside ~/sslserver
python3 server.py
```

Open `https://192.168.1.3:8080` from another lab VM (observer or attacker VM) to validate the page loads (you may need to accept the self-signed certificate in a browser or use `openssl s_client`).

---

## 6 — Observing TLS behavior (openssh / openssl client)

From another VM, show a normal handshake with `openssl`:

```bash
openssl s_client -connect 192.168.1.3:8080 -tls1_2
```

Observe the TLS ClientHello / ServerHello sequence in Wireshark. Then optionally repeat with `-tls1_3` (if supported):

```bash
openssl s_client -connect 192.168.1.3:8080 -tls1_3
```

---

## 7 — Wireshark / CPU metrics — demonstrate server effects (defensive simulation)

Rather than performing a real exploit, teach students to observe how repeated expensive operations affect the server:

### 7.1 Baseline: normal connection

* Start Wireshark on observer VM using the filters in section 3.
* On victim server, run `htop` or `top` to show baseline CPU usage while serving normal traffic.
* Connect from client using `openssl s_client` and observe the handshake packets.

### 7.2 Simulate heavy post-handshake work (safe alternative)

To simulate the server CPU cost of repeated renegotiations without running an exploit, add an endpoint that performs an expensive cryptographic or CPU task (e.g., a busy loop or a PBKDF2 operation) on each request. Students can then issue many legitimate requests (e.g., via `curl`) and observe CPU increase and packet patterns—this demonstrates the resource exhaustion concept without sending malformed or abusive handshake sequences.

Example (conceptual only):

* Add a handler that computes a heavy PBKDF2 operation for each request (understand this is a SAFE LAB SIMUALTION THAT SHOULD NOT BE USED FOR ILLEGAL ACTIVITIES).

---

## 8 — Tool references

* The historical repo referenced in original notes: `https://github.com/azet/thc-tls-dos` — **do not** run unreviewed code; review and audit before any use in lab. Preserve legal/ethical controls.

---

## 9 — Remediation / Hardening checklist (what to change)

1. **Upgrade protocol** to TLS 1.3 where possible. TLS 1.3 eliminates renegotiation from the specification.

   * In Python ssl context: `context.minimum_version = ssl.TLSVersion.TLSv1_3` (if supported).
2. **Disable client-initiated renegotiation** where server software supports such a setting. Check your web server / TLS library documentation.
3. **Use a modern TLS stack** (up-to-date OpenSSL, modern server software).
4. **Rate-limit handshakes and connections** at reverse proxy or load balancer (nginx, HAProxy, cloud WAF).
5. **Offload TLS** to a reverse proxy or dedicated TLS terminator so backend app servers are not exposed to heavy crypto work.
6. **Monitor**: logging, TLS handshake rates, CPU per process, and anomalous long-lived connections.

---

## 10 — Example: change Python server to enforce TLS 1.3 (if supported)

Edit `server.py` SSL context lines as follows (replace earlier commented code):

```python
# require TLS 1.3 only (if supported by Python/OpenSSL)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
```

Restart the server and test with `openssl s_client -tls1_3`. Handshake renegotiation will not be available under TLS 1.3.

---

## 11 — Final notes

* Keep the **educational narrative** centered on *why* the attack works and *how* to detect/mitigate it.
* Avoid publishing runnable exploit recipes in publicly distributed materials. If you include references to offensive tools, clearly mark them as “instructor reference only” and provide legal/ethical guidance.
* Provide students with **safe lab exercises** that simulate the effects (CPU/connection profile) rather than exercising real exploit code.
