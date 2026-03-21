// WebSocket client and orchestration — Phosphor theme

(() => {
  const engageBtn = document.getElementById('engage-btn');
  const targetInput = document.getElementById('target-input');
  const lhostInput = document.getElementById('lhost-input');
  const targetValidation = document.getElementById('target-validation');
  const lhostValidation = document.getElementById('lhost-validation');
  const statusText = document.getElementById('status-text');
  const inputSection = document.getElementById('input-section');
  const metricsSection = document.getElementById('metrics-section');
  const metricTime = document.getElementById('metric-time');
  const metricTools = document.getElementById('metric-tools');
  const metricNodes = document.getElementById('metric-nodes');
  const metricBudget = document.getElementById('metric-budget');
  const metricTarget = document.getElementById('metric-target');

  const PHASES = ['recon', 'exploit', 'escalate'];
  const phaseDots = document.querySelectorAll('.phase-dot');
  const phaseConnectors = document.querySelectorAll('.phase-connector');

  let ws = null;
  let timerInterval = null;
  let startTime = null;
  let currentPhaseIndex = -1;

  // IP validation regex
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;

  function validateIP(value) {
    if (!value) return null;
    if (!ipRegex.test(value)) return false;
    return value.split('.').every(octet => {
      const n = parseInt(octet, 10);
      return n >= 0 && n <= 255;
    });
  }

  function updateValidation(input, icon, value) {
    const result = validateIP(value);
    input.classList.remove('valid', 'invalid');
    icon.classList.remove('valid', 'invalid');
    if (result === null) return;
    if (result) {
      input.classList.add('valid');
      icon.classList.add('valid');
    } else {
      input.classList.add('invalid');
      icon.classList.add('invalid');
    }
  }

  targetInput.addEventListener('input', () => {
    updateValidation(targetInput, targetValidation, targetInput.value.trim());
  });

  lhostInput.addEventListener('input', () => {
    updateValidation(lhostInput, lhostValidation, lhostInput.value.trim());
  });

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel-content').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`${tab.dataset.tab}-panel`).classList.add('active');
      // Clear notification dot when tab is clicked
      const dot = tab.querySelector('.notify-dot');
      if (dot) dot.remove();
    });
  });

  // Phase stepper — 3 phases: RECON → EXPLOIT → PRIVESC
  function setPhase(phaseIndex) {
    if (phaseIndex === currentPhaseIndex) return;

    // Mark previous phases as completed
    for (let i = 0; i <= currentPhaseIndex && i < phaseDots.length; i++) {
      phaseDots[i].classList.remove('active');
      phaseDots[i].classList.add('completed');
    }
    // Mark connectors up to current as completed
    for (let i = 0; i < phaseIndex && i < phaseConnectors.length; i++) {
      phaseConnectors[i].classList.add('completed');
    }

    currentPhaseIndex = phaseIndex;

    if (phaseIndex >= 0 && phaseIndex < phaseDots.length) {
      phaseDots[phaseIndex].classList.remove('completed');
      phaseDots[phaseIndex].classList.add('active');
    }
  }

  function phaseNameToIndex(name) {
    const normalized = name.toLowerCase().replace(/[^a-z]/g, '');
    // 3-phase mapping: enumeration → 0, exploitation → 1, privesc → 2
    if (normalized.includes('enum') || normalized.includes('recon') || normalized.includes('scan')) return 0;
    if (normalized.includes('exploit') || normalized.includes('attack')) return 1;
    if (normalized.includes('escal') || normalized.includes('priv') || normalized.includes('post')) return 2;
    return -1;
  }

  // Elapsed timer
  function startTimer() {
    startTime = Date.now();
    timerInterval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      const min = String(Math.floor(elapsed / 60)).padStart(2, '0');
      const sec = String(elapsed % 60).padStart(2, '0');
      metricTime.textContent = `${min}:${sec}`;
    }, 1000);
  }

  function stopTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  }

  // Metrics update
  function updateMetrics() {
    metricTools.textContent = ToolPanel.getToolCount();
    metricNodes.textContent = GraphViz.getNodeCount();
  }

  // Tab notifications
  function notifyTab(tabName) {
    const tab = document.querySelector(`.tab[data-tab="${tabName}"]`);
    if (tab && !tab.classList.contains('active') && !tab.querySelector('.notify-dot')) {
      const dot = document.createElement('span');
      dot.className = 'notify-dot';
      tab.appendChild(dot);
    }
  }

  // Budget update
  function updateBudget(remaining, total) {
    if (metricBudget) {
      metricBudget.textContent = `${remaining}/${total}`;
      // Color-code: green > 20, yellow > 10, red <= 10
      metricBudget.classList.remove('budget-ok', 'budget-warn', 'budget-crit');
      if (remaining > 20) metricBudget.classList.add('budget-ok');
      else if (remaining > 10) metricBudget.classList.add('budget-warn');
      else metricBudget.classList.add('budget-crit');
    }
  }

  // Switch to metrics bar
  function showMetrics(target) {
    inputSection.style.display = 'none';
    metricsSection.classList.remove('hidden');
    metricTarget.textContent = target;
  }

  // Switch back to input bar
  function showInputs() {
    metricsSection.classList.add('hidden');
    inputSection.style.display = 'flex';
  }

  // Init graph
  GraphViz.init();

  engageBtn.addEventListener('click', () => {
    const target = targetInput.value.trim();
    const lhost = lhostInput.value.trim();
    if (!target || validateIP(target) === false) return;
    if (lhost && validateIP(lhost) === false) return;

    engageBtn.disabled = true;
    statusText.textContent = 'CONNECTING';

    showMetrics(target);
    startTimer();
    setPhase(0);
    updateBudget(30, 30);

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);

    ws.onopen = () => {
      ws.send(JSON.stringify({ target, lhost }));
      statusText.textContent = 'ENGAGED';
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      handleMessage(msg);
      updateMetrics();
    };

    ws.onclose = () => {
      statusText.textContent = 'DISCONNECTED';
      stopTimer();
      engageBtn.disabled = false;
      showInputs();
    };

    ws.onerror = () => {
      statusText.textContent = 'ERROR';
      stopTimer();
      engageBtn.disabled = false;
      showInputs();
    };
  });

  function handleMessage(msg) {
    switch (msg.type) {
      case 'graph_update':
        GraphViz.update(msg.data.nodes, msg.data.edges);
        Intel.update(msg.data.nodes);
        break;

      case 'tool_call':
        ToolPanel.addToolCall(msg.data.id, msg.data.name, msg.data.args);
        break;

      case 'tool_result':
        ToolPanel.updateToolResult(msg.data.id, msg.data.result, msg.data.error);
        break;

      case 'phase_change': {
        const phaseName = msg.data.phase;
        const idx = phaseNameToIndex(phaseName);
        if (idx >= 0) {
          setPhase(idx);
          ToolPanel.setPhase(PHASES[idx]);
        }
        statusText.textContent = phaseName.toUpperCase();
        break;
      }

      case 'report_update':
        Report.update(msg.data.markdown);
        notifyTab('report');
        break;

      case 'agent_thinking':
        ToolPanel.addThinking(msg.data.text);
        break;

      case 'strategy_update':
        Intel.updateStrategy(msg.data.strategy, msg.data.phase);
        notifyTab('intel');
        break;

      case 'budget_update':
        updateBudget(msg.data.remaining, msg.data.total);
        break;

      case 'shell_access':
        Sessions.addSession(msg.data);
        notifyTab('sessions');
        break;

      case 'complete':
        statusText.textContent = 'COMPLETE';
        phaseDots.forEach(d => { d.classList.remove('active'); d.classList.add('completed'); });
        phaseConnectors.forEach(c => c.classList.add('completed'));
        stopTimer();
        engageBtn.disabled = false;
        break;

      case 'error':
        statusText.textContent = 'ERROR';
        ToolPanel.addThinking('Error: ' + (msg.data.message || 'Unknown error'));
        stopTimer();
        engageBtn.disabled = false;
        break;
    }
  }

  // Sessions module — tracks shell access
  const Sessions = (() => {
    const list = document.getElementById('sessions-list');
    const empty = document.getElementById('sessions-empty');
    const sessions = [];

    function addSession(data) {
      sessions.push(data);
      empty.style.display = 'none';
      render();
    }

    function render() {
      let html = '';
      sessions.forEach((s, i) => {
        const levelClass = s.level === 'root' ? 'session-root' : 'session-user';
        const levelBadge = s.level === 'root' ? 'ROOT' : 'USER';
        const sshCmd = s.ssh_command || `ssh ${s.user}@${s.host}`;

        html += `<div class="session-card ${levelClass}">`;
        html += `<div class="session-header">`;
        html += `<span class="session-badge ${levelClass}">${levelBadge}</span>`;
        html += `<span class="session-target">${escapeHtml(s.user)}@${escapeHtml(s.host)}</span>`;
        html += `<span class="session-time">${escapeHtml(s.timestamp || '')}</span>`;
        html += `</div>`;
        html += `<div class="session-details">`;
        html += `<div class="session-method">via ${escapeHtml(s.method || 'unknown')}</div>`;
        if (sshCmd) {
          html += `<div class="session-cmd-container">`;
          html += `<code class="session-cmd">${escapeHtml(sshCmd)}</code>`;
          html += `<button class="session-copy-btn" onclick="Sessions.copyCmd(${i})" title="Copy SSH command">COPY</button>`;
          html += `</div>`;
        }
        html += `</div>`;
        html += `</div>`;
      });
      list.innerHTML = html;
    }

    function copyCmd(index) {
      const s = sessions[index];
      const cmd = s.ssh_command || `ssh ${s.user}@${s.host}`;
      navigator.clipboard.writeText(cmd).then(() => {
        const btn = list.querySelectorAll('.session-copy-btn')[index];
        if (btn) {
          btn.textContent = 'COPIED';
          setTimeout(() => { btn.textContent = 'COPY'; }, 1500);
        }
      });
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    // Expose globally for onclick handlers
    window.Sessions = { addSession, copyCmd };
    return { addSession, copyCmd };
  })();
})();
