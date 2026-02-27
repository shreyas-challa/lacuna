// WebSocket client and orchestration

(() => {
  const startBtn = document.getElementById('start-btn');
  const targetInput = document.getElementById('target-input');
  const phaseLabel = document.getElementById('phase-label');
  let ws = null;

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel-content').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`${tab.dataset.tab}-panel`).classList.add('active');
    });
  });

  // Init graph
  GraphViz.init();

  startBtn.addEventListener('click', () => {
    const target = targetInput.value.trim();
    if (!target) return;

    startBtn.disabled = true;
    targetInput.disabled = true;
    phaseLabel.textContent = 'CONNECTING...';

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);

    ws.onopen = () => {
      ws.send(JSON.stringify({ target }));
      phaseLabel.textContent = 'STARTING';
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      handleMessage(msg);
    };

    ws.onclose = () => {
      phaseLabel.textContent = 'DISCONNECTED';
      startBtn.disabled = false;
      targetInput.disabled = false;
    };

    ws.onerror = () => {
      phaseLabel.textContent = 'ERROR';
      startBtn.disabled = false;
      targetInput.disabled = false;
    };
  });

  function handleMessage(msg) {
    switch (msg.type) {
      case 'graph_update':
        GraphViz.update(msg.data.nodes, msg.data.edges);
        break;

      case 'tool_call':
        ToolPanel.addToolCall(msg.data.id, msg.data.name, msg.data.args);
        break;

      case 'tool_result':
        ToolPanel.updateToolResult(msg.data.id, msg.data.result, msg.data.error);
        break;

      case 'phase_change':
        phaseLabel.textContent = msg.data.phase.toUpperCase();
        break;

      case 'report_update':
        Report.update(msg.data.markdown);
        break;

      case 'agent_thinking':
        ToolPanel.addThinking(msg.data.text);
        break;

      case 'complete':
        phaseLabel.textContent = 'COMPLETE';
        startBtn.disabled = false;
        targetInput.disabled = false;
        break;

      case 'error':
        phaseLabel.textContent = 'ERROR';
        ToolPanel.addThinking('Error: ' + (msg.data.message || 'Unknown error'));
        break;
    }
  }
})();
