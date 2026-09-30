/**
 * Application Controller & UI Orchestration
 * Connects Web Crypto Engine, AI Anomaly Detector, Interactive Canvas Charts, and UI.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Initialize Core Systems
  const cryptoEngine = new SmartCryptoEngine();
  await cryptoEngine.initialize();

  const aiDetector = new AIThreatDetector(cryptoEngine, { threshold: 70 });

  // DOM Elements
  const activeKeyVersionEl = document.getElementById('active-key-version');
  const activeKeyIdEl = document.getElementById('active-key-id');
  const activeKeyFingerprintEl = document.getElementById('active-key-fingerprint');
  const activeKeyHexEl = document.getElementById('active-key-hex');
  const totalRotationsEl = document.getElementById('total-rotations');
  const keyVaultListEl = document.getElementById('key-vault-list');

  // AI Gauge & Threat Elements
  const aiScoreNumberEl = document.getElementById('ai-score-number');
  const aiScoreGaugeEl = document.getElementById('ai-score-gauge');
  const threatBadgeEl = document.getElementById('threat-badge');
  const thresholdValueEl = document.getElementById('threshold-value');
  const autoRotateToggle = document.getElementById('auto-rotate-toggle');
  const thresholdSlider = document.getElementById('threshold-slider');

  // Cryptographic Workspace Elements
  const plaintextInput = document.getElementById('plaintext-input');
  const encryptBtn = document.getElementById('encrypt-btn');
  const ciphertextOutput = document.getElementById('ciphertext-output');
  const decryptBtn = document.getElementById('decrypt-btn');
  const decryptedOutput = document.getElementById('decrypted-output');
  const encryptLatencyEl = document.getElementById('encrypt-latency');
  const decryptLatencyEl = document.getElementById('decrypt-latency');
  const payloadEntropyEl = document.getElementById('payload-entropy');
  const copyCipherBtn = document.getElementById('copy-cipher-btn');
  const pasteSampleBtn = document.getElementById('paste-sample-btn');

  // Simulation Controls
  const simBruteForceBtn = document.getElementById('sim-bruteforce');
  const simTamperBtn = document.getElementById('sim-tamper');
  const simDosBtn = document.getElementById('sim-dos');
  const simReplayBtn = document.getElementById('sim-replay');
  const simNormalBtn = document.getElementById('sim-normal');
  const manualRotateBtn = document.getElementById('manual-rotate-btn');
  const runBenchmarkBtn = document.getElementById('run-benchmark-btn');
  const benchmarkResultEl = document.getElementById('benchmark-result');

  // Audit Logs
  const auditLogsContainer = document.getElementById('audit-logs-container');
  const clearLogsBtn = document.getElementById('clear-logs-btn');

  // Live Canvas Telemetry
  const telemetryCanvas = document.getElementById('telemetry-canvas');
  const ctx = telemetryCanvas.getContext('2d');

  // Sound / Visual pulse helper
  function triggerPulse(element, color = 'var(--cyan-glow)') {
    if (!element) return;
    element.style.transition = 'none';
    element.style.boxShadow = `0 0 25px ${color}`;
    setTimeout(() => {
      element.style.transition = 'box-shadow 0.8s ease';
      element.style.boxShadow = '';
    }, 100);
  }

  // Update Active Key Cards & Vault
  function renderKeyVault() {
    const activeKey = cryptoEngine.getActiveKey();
    if (activeKey) {
      activeKeyVersionEl.textContent = activeKey.version;
      activeKeyIdEl.textContent = activeKey.id;
      activeKeyFingerprintEl.textContent = activeKey.fingerprint;
      activeKeyHexEl.textContent = `${activeKey.rawHex.substring(0, 32)}...`;
      totalRotationsEl.textContent = cryptoEngine.rotationCount;
    }

    keyVaultListEl.innerHTML = '';
    cryptoEngine.keyHistory.forEach((key, index) => {
      const isCurrent = key.status === 'ACTIVE';
      const item = document.createElement('div');
      item.className = `vault-key-card ${isCurrent ? 'active-key' : 'retired-key'}`;
      item.innerHTML = `
        <div class="key-card-header">
          <div class="key-card-title">
            <span class="key-version-badge ${isCurrent ? 'badge-cyan' : 'badge-gray'}">${key.version}</span>
            <span class="key-id-label">${key.id}</span>
          </div>
          <span class="key-status-pill ${isCurrent ? 'status-active' : 'status-retired'}">
            ${isCurrent ? '● ACTIVE' : 'RETIRED'}
          </span>
        </div>
        <div class="key-card-body">
          <div class="key-field">
            <span class="field-label">Fingerprint:</span>
            <code class="field-code">${key.fingerprint}</code>
          </div>
          <div class="key-field">
            <span class="field-label">Algorithm:</span>
            <span class="field-value">${key.algorithm}</span>
          </div>
          <div class="key-field">
            <span class="field-label">Created:</span>
            <span class="field-value">${new Date(key.createdAt).toLocaleTimeString()}</span>
          </div>
          <div class="key-field">
            <span class="field-label">Rotation Reason:</span>
            <span class="field-value reason-tag">${key.reason}</span>
          </div>
        </div>
      `;
      keyVaultListEl.appendChild(item);
    });
  }

  // Update AI Threat Visuals
  function updateThreatUI(report) {
    const score = report.score;
    aiScoreNumberEl.textContent = `${score}%`;
    thresholdValueEl.textContent = `${report.threshold}%`;

    // Adjust stroke dash offset for radial gauge (circumference = 2 * PI * 40 ≈ 251.2)
    const circumference = 251.2;
    const offset = circumference - (score / 100) * circumference;
    aiScoreGaugeEl.style.strokeDashoffset = offset;

    // Change gauge color based on threat severity
    let colorClass = 'threat-low';
    let gaugeColor = '#00f2fe';

    if (score >= 80) {
      colorClass = 'threat-critical';
      gaugeColor = '#ff0055';
    } else if (score >= 50) {
      colorClass = 'threat-high';
      gaugeColor = '#ff9900';
    } else if (score >= 25) {
      colorClass = 'threat-elevated';
      gaugeColor = '#ffdd00';
    }

    aiScoreGaugeEl.style.stroke = gaugeColor;
    threatBadgeEl.className = `threat-pill ${colorClass}`;
    threatBadgeEl.textContent = report.level;

    // Draw Real-time Chart
    drawTelemetryChart(report.telemetryHistory);
  }

  // Render Telemetry Canvas
  function drawTelemetryChart(history) {
    if (!ctx || !history || history.length === 0) return;
    const w = telemetryCanvas.width = telemetryCanvas.parentElement.clientWidth || 500;
    const h = telemetryCanvas.height = 160;

    ctx.clearRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = (h / 4) * i;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Threshold line
    const thresholdY = h - (aiDetector.threshold / 100) * h;
    ctx.strokeStyle = 'rgba(255, 0, 85, 0.4)';
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, thresholdY);
    ctx.lineTo(w, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw Risk Score Gradient Area
    const step = w / (history.length - 1);
    ctx.beginPath();
    history.forEach((pt, i) => {
      const x = i * step;
      const y = h - (pt.riskScore / 100) * (h - 10) - 5;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });

    ctx.strokeStyle = '#00f2fe';
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Fill area under curve
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, 'rgba(0, 242, 254, 0.25)');
    gradient.addColorStop(1, 'rgba(0, 242, 254, 0.0)');
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw glowing points on peaks
    history.forEach((pt, i) => {
      if (pt.riskScore >= 50) {
        const x = i * step;
        const y = h - (pt.riskScore / 100) * (h - 10) - 5;
        ctx.fillStyle = pt.riskScore >= 70 ? '#ff0055' : '#ff9900';
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fill();
      }
    });
  }

  // Append Audit Log
  function appendAuditLog(event) {
    const logItem = document.createElement('div');
    const isCritical = event.type.includes('ROTATION') || event.threatLevel === 'CRITICAL';
    const isWarn = event.threatLevel === 'HIGH' || event.type.includes('FAILURE');

    logItem.className = `log-entry ${isCritical ? 'log-critical' : isWarn ? 'log-warn' : 'log-info'}`;
    logItem.innerHTML = `
      <span class="log-time">[${event.time}]</span>
      <span class="log-type ${isCritical ? 'type-crit' : 'type-norm'}">${event.type}</span>
      <span class="log-impact">${event.riskImpact}</span>
      <span class="log-desc">${event.details}</span>
    `;

    auditLogsContainer.insertBefore(logItem, auditLogsContainer.firstChild);

    // Limit logs in DOM
    while (auditLogsContainer.children.length > 60) {
      auditLogsContainer.removeChild(auditLogsContainer.lastChild);
    }
  }

  // Setup callbacks
  aiDetector.onThreatEvaluated = (report) => {
    updateThreatUI(report);
  };

  aiDetector.onAutoRotate = (newKey, reason) => {
    renderKeyVault();
    triggerPulse(document.getElementById('active-key-card'), '#ff0055');
  };

  aiDetector.onLogMessage = (event) => {
    appendAuditLog(event);
  };

  // Perform Initial Render
  renderKeyVault();
  updateThreatUI(aiDetector.getThreatReport());

  // --- INTERACTIVE ACTIONS ---

  // 1. Encryption Action
  encryptBtn.addEventListener('click', async () => {
    const text = plaintextInput.value.trim();
    if (!text) {
      plaintextInput.focus();
      return;
    }

    try {
      const result = await cryptoEngine.encrypt(text);
      ciphertextOutput.value = result.envelope;
      encryptLatencyEl.textContent = `${result.latencyUs} µs`;

      const entropy = SmartCryptoEngine.calculateEntropy(text);
      payloadEntropyEl.textContent = `${entropy} bits/char`;

      await aiDetector.recordEvent('NORMAL_ENCRYPT', { latencyUs: result.latencyUs });
      triggerPulse(ciphertextOutput, 'var(--cyan-glow)');
    } catch (err) {
      alert(`Encryption Error: ${err.message}`);
    }
  });

  // 2. Decryption Action
  decryptBtn.addEventListener('click', async () => {
    const cipherText = ciphertextOutput.value.trim();
    if (!cipherText) {
      ciphertextOutput.focus();
      return;
    }

    try {
      const result = await cryptoEngine.decrypt(cipherText);
      decryptedOutput.value = result.plaintext;
      decryptLatencyEl.textContent = `${result.latencyUs} µs`;

      await aiDetector.recordEvent('NORMAL_DECRYPT', { keyUsed: result.keyUsed, latencyUs: result.latencyUs });
      triggerPulse(decryptedOutput, 'var(--green-glow)');
    } catch (err) {
      decryptedOutput.value = `❌ DECRYPTION FAILED: ${err.message}`;
      await aiDetector.recordEvent('DECRYPT_FAILURE', { error: err.message });
      triggerPulse(decryptedOutput, '#ff0055');
    }
  });

  // 3. Manual Key Rotation
  manualRotateBtn.addEventListener('click', async () => {
    manualRotateBtn.disabled = true;
    manualRotateBtn.textContent = 'Rotating...';

    const newKey = await cryptoEngine.rotateKey('Manual User Trigger');
    renderKeyVault();
    await aiDetector.recordEvent('MANUAL_KEY_ROTATION', { key: newKey.version });

    setTimeout(() => {
      manualRotateBtn.disabled = false;
      manualRotateBtn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
        </svg> Rotate Key Now
      `;
    }, 400);
  });

  // 4. Attack Simulations
  simBruteForceBtn.addEventListener('click', async () => {
    simBruteForceBtn.classList.add('btn-pulsing');
    for (let i = 0; i < 6; i++) {
      await aiDetector.recordEvent('BRUTE_FORCE_BURST', { attempts: 18 + i * 5 });
      await new Promise(r => setTimeout(r, 120));
    }
    simBruteForceBtn.classList.remove('btn-pulsing');
  });

  simTamperBtn.addEventListener('click', async () => {
    // If there's ciphertext in output, corrupt 2 bytes
    if (ciphertextOutput.value.length > 20) {
      let val = ciphertextOutput.value;
      const pos = Math.floor(val.length / 2);
      val = val.substring(0, pos) + 'X9' + val.substring(pos + 2);
      ciphertextOutput.value = val;
    }
    await aiDetector.recordEvent('ENTROPY_ANOMALY', { entropy: 7.94 });
  });

  simDosBtn.addEventListener('click', async () => {
    simDosBtn.classList.add('btn-pulsing');
    for (let i = 0; i < 8; i++) {
      await aiDetector.recordEvent('HIGH_FREQUENCY_DOS', { rps: 450 });
      await new Promise(r => setTimeout(r, 80));
    }
    simDosBtn.classList.remove('btn-pulsing');
  });

  simReplayBtn.addEventListener('click', async () => {
    await aiDetector.recordEvent('REPLAY_ATTACK', { duplicateIv: '0x8FA4...EE12' });
  });

  simNormalBtn.addEventListener('click', async () => {
    await aiDetector.recordEvent('NORMAL_ENCRYPT', { latencyUs: 85.4 });
    await aiDetector.recordEvent('NORMAL_DECRYPT', { keyUsed: 'v1.0', latencyUs: 72.1 });
  });

  // 5. Benchmark Performance
  runBenchmarkBtn.addEventListener('click', async () => {
    benchmarkResultEl.textContent = 'Benchmarking 50 operations...';
    runBenchmarkBtn.disabled = true;

    const testPayload = "High-Security Confidential AI Data Block for Microsecond Cryptographic Latency Evaluation";
    const runs = 50;
    const start = performance.now();

    for (let i = 0; i < runs; i++) {
      const enc = await cryptoEngine.encrypt(testPayload);
      await cryptoEngine.decrypt(enc.envelope);
    }

    const totalTime = performance.now() - start;
    const avgPerOp = ((totalTime / (runs * 2)) * 1000).toFixed(1);

    benchmarkResultEl.innerHTML = `⚡ Avg Latency: <strong style="color:var(--cyan);">${avgPerOp} µs</strong> (${(runs * 2)} ops in ${totalTime.toFixed(1)}ms)`;
    runBenchmarkBtn.disabled = false;
  });

  // 6. Utility actions
  copyCipherBtn.addEventListener('click', () => {
    if (!ciphertextOutput.value) return;
    navigator.clipboard.writeText(ciphertextOutput.value);
    const original = copyCipherBtn.textContent;
    copyCipherBtn.textContent = 'Copied!';
    setTimeout(() => copyCipherBtn.textContent = original, 1500);
  });

  pasteSampleBtn.addEventListener('click', () => {
    plaintextInput.value = JSON.stringify({
      user_id: "usr_94829a8f",
      role: "SYSTEM_ADMIN",
      session_token: "tok_" + Math.random().toString(36).substring(2, 15),
      permissions: ["READ_ENCRYPTED_VAULT", "EXECUTE_ROTATION"],
      timestamp: new Date().toISOString()
    }, null, 2);
  });

  clearLogsBtn.addEventListener('click', () => {
    auditLogsContainer.innerHTML = '';
  });

  thresholdSlider.addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 10);
    aiDetector.threshold = val;
    thresholdValueEl.textContent = `${val}%`;
  });

  autoRotateToggle.addEventListener('change', (e) => {
    aiDetector.autoRotationEnabled = e.target.checked;
  });

  // Window resize chart handler
  window.addEventListener('resize', () => {
    drawTelemetryChart(aiDetector.telemetryHistory);
  });

  // Initial seed log
  aiDetector.recordEvent('NORMAL_ENCRYPT', { latencyUs: 64.2 });
});
