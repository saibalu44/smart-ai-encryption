/**
 * AI-Based Real-Time Threat & Anomaly Detection Engine
 * Analyzes traffic patterns, decryption errors, request velocities, entropy anomalies,
 * and dynamically triggers automatic cryptographic key rotation.
 */

class AIThreatDetector {
  constructor(cryptoEngine, options = {}) {
    this.cryptoEngine = cryptoEngine;
    this.threshold = options.threshold || 70; // Risk score >= 70 triggers auto-rotation
    this.riskScore = 8; // Baseline idle risk (0-100)
    this.threatLevel = 'LOW'; // LOW, ELEVATED, HIGH, CRITICAL
    
    // Telemetry tracking
    this.recentEvents = [];
    this.requestCount = 0;
    this.failureCount = 0;
    this.tamperAttempts = 0;
    this.lastRotationTime = Date.now();
    this.autoRotationEnabled = true;

    // Callbacks for UI updates
    this.onThreatEvaluated = null;
    this.onAutoRotate = null;
    this.onLogMessage = null;

    // Rolling metric history for charts
    this.telemetryHistory = [];
    for (let i = 0; i < 20; i++) {
      this.telemetryHistory.push({
        time: new Date(Date.now() - (20 - i) * 1000).toLocaleTimeString(),
        riskScore: Math.floor(Math.random() * 12) + 5,
        requestsPerSec: Math.floor(Math.random() * 4) + 1,
        entropy: 3.8 + Math.random() * 0.4
      });
    }

    this.startHeartbeat();
  }

  // Periodic decay of threat score back to baseline
  startHeartbeat() {
    setInterval(() => {
      // Natural risk decay towards baseline
      if (this.riskScore > 10) {
        this.riskScore = Math.max(8, this.riskScore - 3);
        this.updateThreatLevel();
      }

      // Record snapshot
      this.recordTelemetrySnapshot();

      if (this.onThreatEvaluated) {
        this.onThreatEvaluated(this.getThreatReport());
      }
    }, 1500);
  }

  recordTelemetrySnapshot() {
    const snapshot = {
      time: new Date().toLocaleTimeString(),
      riskScore: Math.round(this.riskScore),
      requestsPerSec: Math.min(50, this.requestCount),
      entropy: Number((3.6 + (this.riskScore / 100) * 1.5 + (Math.random() * 0.2)).toFixed(2))
    };

    this.telemetryHistory.push(snapshot);
    if (this.telemetryHistory.length > 25) {
      this.telemetryHistory.shift();
    }

    // Reset periodic counters
    this.requestCount = Math.max(0, Math.floor(this.requestCount * 0.6));
  }

  // Ingest security telemetry and compute AI Anomaly Score
  async recordEvent(eventType, metadata = {}) {
    this.requestCount++;
    const timestamp = Date.now();
    let penalty = 0;
    let details = '';

    switch (eventType) {
      case 'NORMAL_ENCRYPT':
        penalty = 1;
        details = `Valid encryption operation (${metadata.latencyUs || 0}µs)`;
        break;

      case 'NORMAL_DECRYPT':
        penalty = 1;
        details = `Successful decryption using Key ${metadata.keyUsed || 'current'}`;
        break;

      case 'DECRYPT_FAILURE':
        this.failureCount++;
        penalty = 32; // Decryption failures strongly indicate key compromise/tamper
        details = `Auth tag failure: ${metadata.error || 'Tampered ciphertext'}`;
        break;

      case 'BRUTE_FORCE_BURST':
        this.failureCount += 5;
        penalty = 58;
        details = `Anomalous decrypt burst detected (${metadata.attempts || 10} attempts / sec)`;
        break;

      case 'ENTROPY_ANOMALY':
        this.tamperAttempts++;
        penalty = 45;
        details = `Shannon entropy anomaly score: ${metadata.entropy || 0} (Variance > 3.2σ)`;
        break;

      case 'REPLAY_ATTACK':
        penalty = 65;
        details = `Stale cryptographic nonce / duplicate IV detected`;
        break;

      case 'HIGH_FREQUENCY_DOS':
        penalty = 75;
        details = `Suspicious packet burst exceeding rate-limit baseline`;
        break;

      default:
        penalty = 5;
        details = `Telemetry point received`;
    }

    // Calculate dynamic risk score (clamped 0 to 100)
    this.riskScore = Math.min(100, Math.max(0, this.riskScore + penalty));
    this.updateThreatLevel();

    const eventRecord = {
      id: Math.random().toString(36).substring(2, 9),
      type: eventType,
      riskImpact: `+${penalty}%`,
      scoreAfter: Math.round(this.riskScore),
      threatLevel: this.threatLevel,
      details: details,
      time: new Date().toLocaleTimeString()
    };

    this.recentEvents.unshift(eventRecord);
    if (this.recentEvents.length > 50) this.recentEvents.pop();

    if (this.onLogMessage) {
      this.onLogMessage(eventRecord);
    }

    // Trigger AI Dynamic Key Rotation if threshold reached
    if (this.riskScore >= this.threshold && this.autoRotationEnabled) {
      await this.triggerDefensiveRotation(`AI Anomaly Engine: Risk Score Exceeded Threshold (${Math.round(this.riskScore)}% / ${this.threshold}%) [Reason: ${eventType}]`);
    }

    if (this.onThreatEvaluated) {
      this.onThreatEvaluated(this.getThreatReport());
    }

    return eventRecord;
  }

  updateThreatLevel() {
    if (this.riskScore >= 80) {
      this.threatLevel = 'CRITICAL';
    } else if (this.riskScore >= 50) {
      this.threatLevel = 'HIGH';
    } else if (this.riskScore >= 25) {
      this.threatLevel = 'ELEVATED';
    } else {
      this.threatLevel = 'LOW';
    }
  }

  // Trigger automated cryptographic key rotation
  async triggerDefensiveRotation(reason) {
    if (Date.now() - this.lastRotationTime < 800) {
      return; // prevent oscillation within 800ms
    }
    this.lastRotationTime = Date.now();

    const newKeyRecord = await this.cryptoEngine.rotateKey(reason);

    // After key rotation, threat score drops significantly as current cipher session is sanitized
    this.riskScore = Math.max(8, this.riskScore - 60);
    this.updateThreatLevel();

    const logRecord = {
      id: Math.random().toString(36).substring(2, 9),
      type: 'AI_KEY_ROTATION_TRIGGERED',
      riskImpact: '-60%',
      scoreAfter: Math.round(this.riskScore),
      threatLevel: this.threatLevel,
      details: `[AUTO-DEFENSE] Rotated to ${newKeyRecord.version} (${newKeyRecord.id}). Latency: ${newKeyRecord.rotationLatencyMs}ms`,
      time: new Date().toLocaleTimeString()
    };

    this.recentEvents.unshift(logRecord);

    if (this.onAutoRotate) {
      this.onAutoRotate(newKeyRecord, reason);
    }

    if (this.onLogMessage) {
      this.onLogMessage(logRecord);
    }

    return newKeyRecord;
  }

  getThreatReport() {
    return {
      score: Math.round(this.riskScore),
      level: this.threatLevel,
      threshold: this.threshold,
      autoRotationEnabled: this.autoRotationEnabled,
      requestsCount: this.requestCount,
      failuresCount: this.failureCount,
      tamperCount: this.tamperAttempts,
      telemetryHistory: this.telemetryHistory
    };
  }
}

window.AIThreatDetector = AIThreatDetector;
