# Zero Trust Gateway 🛡️

> **A high-performance, asynchronous Identity-Aware Proxy (IAP) implementing Zero Trust architecture principles for securing legacy infrastructure.**

![Python](https://img.shields.io/badge/Python-AsyncIO-blue)
![Architecture](https://img.shields.io/badge/Architecture-Zero_Trust-red)
![Compliance](https://img.shields.io/badge/Compliance-NIS2-orange)

---

## 📖 Executive Summary
Legacy applications (such as ERP systems and corporate intranet portals) often lack modern authentication and contextual access control mechanisms.

**Zero Trust Gateway** introduces a micro-perimeter in front of these legacy workloads, enforcing strict **Identity**, **Device**, and **Context-based** authorization before any request reaches the backend service.

This implementation follows **NIST SP 800-207 Zero Trust Architecture** guidelines, leveraging Python’s asynchronous networking capabilities (`aiohttp`) for high throughput and minimal latency.

---

## 🏗️ Technical Architecture

### 🔁 Reverse Proxy Engine  
Built on **aiohttp**, enabling non-blocking I/O and support for thousands of concurrent inbound connections.

### 🔐 Stateless Authentication  
All requests must include a **JSON Web Token (JWT)** signed by a trusted Identity Provider.  
Claims evaluated include:
- `sub` (User ID)  
- `roles` (RBAC mapping)  
- `exp` (Token expiry)  
- `ip` (Optional: last known IP binding)

### ⚖️ Policy Enforcement Point (PEP)
Each request is validated against:
- **IP Whitelisting Policies**
- **Role-Based Access Control (RBAC)**
- **Time-based or Context-based Policies** (optional future extension)

If the request fails any check, the gateway **denies access** before touching the upstream service.

### 🛡️ Upstream Protection  
The real application endpoint (e.g., SAP, Oracle ERP, legacy web servers) is completely hidden from the public internet.

---

## ⚙️ Installation

```bash
git clone https://github.com/osmankaankars/Zero-Trust-Gateway.git
cd Zero-Trust-Gateway
pip install -r requirements.txt
```

---

## 🚀 Usage Workflow

### 1️⃣ Start the Gateway  
The gateway listens on **Port 9000** and proxies traffic to `http://localhost:8080` (configurable in config.json).

```bash
python gateway.py
```

### 2️⃣ Generate Identity Token  
Use the included lightweight IDP simulator to generate signed JWTs.

```bash
python idp_simulator.py --role admin
```

### 3️⃣ Access Protected Resource  
Use the token to reach the upstream system:

```bash
curl -H "Authorization: Bearer <TOKEN>" http://localhost:9000/
```

If the token is valid and the policy allows access, the request is proxied upstream.  
Otherwise, the gateway returns a **403 Access Denied** response.

---

## 👨‍💻 Author  
**Osman Kaan Kars**  
Cybersecurity Engineer | Systems Architect
