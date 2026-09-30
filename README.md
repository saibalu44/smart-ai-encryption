# 🛡️ Smart AI Encryption System with Dynamic Key Rotation

A production-grade, zero-backend, zero-database client-side cryptographic security suite with AI-based real-time anomaly detection and dynamic AES-256 key rotation.

---

## ⚡ Core Features

- **Browser-Native AES-256-GCM Cryptography**: Hardware-accelerated authenticated encryption with 128-bit authentication tags and 96-bit unique nonces (IVs) via the Web Cryptography API (`crypto.subtle`).
- **AI Anomaly & Threat Detection Engine**:
  - Real-time heuristic scoring (0%–100% Risk Level).
  - Shannon Entropy variance detection (flags ciphertext bit-tampering / bit-flipping).
  - Decryption failure bursts & brute-force anomaly analysis.
  - Rate-limit & velocity breach detection (DDoS / automated scraping).
- **Dynamic AI Key Rotation**:
  - Automatically triggers root key rotation when threat score passes the threshold (default: 70%).
  - Zero-knowledge key versioning (`v1.0`, `v2.0`, `v3.0`...) and SHA-256 fingerprinting.
  - Key history preservation for multi-generational payload decryption.
- **Interactive Threat Simulator**:
  - Test Brute-Force bursts, Ciphertext Tampering, DoS Flooding, and Nonce Replay attacks.
- **Real-Time Telemetry & Visual Charts**:
  - Live Canvas anomaly waveform charts.
  - Real-time cryptographic latency & throughput benchmarking (sub-millisecond microsecond latency).
  - Cryptographic security audit feed with timestamps and SHA signatures.

---

## 🚀 Instant Deployment on Vercel

This app is 100% serverless, requiring **no databases** and **no complex backends**.

### Option 1: Deploy with Vercel CLI
```bash
npm install -g vercel
vercel
```

### Option 2: Deploy with Git / GitHub
1. Push this folder to a GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "feat: initial smart AI encryption system"
   git push origin main
   ```
2. Import the repository directly in [Vercel Dashboard](https://vercel.com/new).
3. Click **Deploy**. Vercel will automatically detect `vercel.json` and serve the application globally on edge CDN.

---

## 💻 Running Locally

You can launch a local HTTP server with any of the following:

```bash
# Using npx serve (recommended)
npx serve .

# Or using Python built-in server
python -m http.server 3000
```
Then visit [http://localhost:3000](http://localhost:3000).

---

## 🔒 Security Specifications

| Parameter | Specification |
| :--- | :--- |
| **Cipher** | AES-256-GCM (Galois/Counter Mode) |
| **Key Length** | 256 bits (32 bytes) |
| **IV / Nonce** | 96 bits (12 bytes) CSPRNG-generated |
| **Tag Length** | 128 bits |
| **AI Threat Metric** | Multi-factor anomaly scoring + Shannon Entropy $\Sigma p_i \log_2(p_i)$ |
