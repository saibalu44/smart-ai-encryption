/**
 * Smart Cryptographic Engine with Dynamic Key Management & Web Crypto API
 * Implements AES-256-GCM encryption, dynamic key generation, fingerprinting, and generational key history.
 */

class SmartCryptoEngine {
  constructor() {
    this.keyHistory = [];
    this.currentKeyVersion = 0;
    this.currentKeyObj = null;
    this.currentKeyFingerprint = '';
    this.rotationCount = 0;
    this.rotationReason = 'Initial System Bootstrap';
  }

  // Initialize engine and generate first generation root key
  async initialize() {
    await this.rotateKey('System Initialization');
  }

  // Generate a random 256-bit AES-GCM CryptoKey
  async generateKey() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // extractable for fingerprinting/archival
      ['encrypt', 'decrypt']
    );
  }

  // Calculate SHA-256 fingerprint of key raw bytes for visual identification
  async calculateFingerprint(cryptoKey) {
    const exported = await window.crypto.subtle.exportKey('raw', cryptoKey);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', exported);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16).toUpperCase();
  }

  // Rotate Key dynamically
  async rotateKey(reason = 'AI Threat Response') {
    const startTime = performance.now();
    const newKey = await this.generateKey();
    const fingerprint = await this.calculateFingerprint(newKey);
    const exportedRaw = await window.crypto.subtle.exportKey('raw', newKey);
    const rawHex = Array.from(new Uint8Array(exportedRaw)).map(b => b.toString(16).padStart(2, '0')).join('');

    this.currentKeyVersion += 1;
    this.rotationCount += 1;
    this.currentKeyObj = newKey;
    this.currentKeyFingerprint = fingerprint;
    this.rotationReason = reason;

    const keyRecord = {
      version: `v${this.currentKeyVersion}.0`,
      id: `KEY-${fingerprint.substring(0, 8)}`,
      fingerprint: fingerprint,
      rawHex: rawHex,
      cryptoKey: newKey,
      algorithm: 'AES-256-GCM',
      createdAt: new Date(),
      reason: reason,
      status: 'ACTIVE',
      encryptionCount: 0,
      rotationLatencyMs: (performance.now() - startTime).toFixed(3)
    };

    // Mark previous active keys as RETIRED
    this.keyHistory.forEach(k => {
      if (k.status === 'ACTIVE') k.status = 'RETIRED';
    });

    this.keyHistory.unshift(keyRecord);
    return keyRecord;
  }

  // Encrypt plaintext payload with current active key
  async encrypt(plaintext) {
    const startTime = performance.now();
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(plaintext);

    // 12-byte initialization vector for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const activeKey = this.getActiveKey();
    if (!activeKey) {
      throw new Error("No active cryptographic key found.");
    }

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      activeKey.cryptoKey,
      encodedData
    );

    const endTime = performance.now();
    const latencyUs = ((endTime - startTime) * 1000).toFixed(1);

    activeKey.encryptionCount++;

    const payload = {
      keyVersion: activeKey.version,
      keyId: activeKey.id,
      algorithm: 'AES-256-GCM',
      iv: this.bufToHex(iv),
      ciphertext: this.bufToHex(new Uint8Array(ciphertextBuffer)),
      timestamp: new Date().toISOString(),
      latencyUs: latencyUs,
      rawBytesLength: encodedData.length
    };

    return {
      payload,
      envelope: btoa(JSON.stringify(payload)),
      latencyUs
    };
  }

  // Decrypt ciphertext envelope
  async decrypt(envelopeString) {
    const startTime = performance.now();
    let payload;

    try {
      if (envelopeString.trim().startsWith('{')) {
        payload = JSON.parse(envelopeString);
      } else {
        const decodedStr = atob(envelopeString.trim());
        payload = JSON.parse(decodedStr);
      }
    } catch (e) {
      throw new Error("Invalid cryptographic envelope format (Corrupted Base64/JSON).");
    }

    if (!payload.ciphertext || !payload.iv || !payload.keyVersion) {
      throw new Error("Missing required cryptographic metadata (IV, KeyVersion, Ciphertext).");
    }

    // Lookup corresponding key by version from history
    const matchingKeyRecord = this.keyHistory.find(k => k.version === payload.keyVersion);

    if (!matchingKeyRecord) {
      throw new Error(`Key ${payload.keyVersion} is expired, revoked or unknown.`);
    }

    const iv = this.hexToBuf(payload.iv);
    const ciphertext = this.hexToBuf(payload.ciphertext);

    try {
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        matchingKeyRecord.cryptoKey,
        ciphertext
      );

      const decoder = new TextDecoder();
      const plaintext = decoder.decode(decryptedBuffer);
      const latencyUs = ((performance.now() - startTime) * 1000).toFixed(1);

      return {
        plaintext,
        keyUsed: matchingKeyRecord.version,
        keyId: matchingKeyRecord.id,
        isCurrentKey: matchingKeyRecord.status === 'ACTIVE',
        latencyUs
      };
    } catch (err) {
      throw new Error("Authentication tag mismatch! Ciphertext has been tampered with or key was revoked.");
    }
  }

  // Helper converters
  bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  hexToBuf(hexStr) {
    const bytes = new Uint8Array(Math.ceil(hexStr.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  getActiveKey() {
    return this.keyHistory.find(k => k.status === 'ACTIVE');
  }

  // Calculate Shannon Entropy of a string to detect anomaly/tampering
  static calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }
}

window.SmartCryptoEngine = SmartCryptoEngine;
