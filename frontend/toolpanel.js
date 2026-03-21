// Tool call log display — Phosphor theme

const ToolPanel = (() => {
  const log = document.getElementById('tool-log');
  const entries = {};
  let currentPhase = 'recon';
  let toolCount = 0;

  function setPhase(phase) {
    currentPhase = phase;
  }

  function addToolCall(id, name, args) {
    toolCount++;
    const entry = document.createElement('div');
    entry.className = 'tool-entry running';
    entry.setAttribute('data-phase', currentPhase);
    entry.innerHTML = `
      <div class="tool-header" onclick="ToolPanel.toggle('${id}')">
        <span class="tool-name">${escapeHtml(name)}</span>
        <span class="tool-status running">RUNNING</span>
      </div>
      <div class="tool-body" id="tool-body-${id}">
        <strong>Args:</strong> ${escapeHtml(JSON.stringify(args, null, 2))}
      </div>
    `;
    log.prepend(entry);
    entries[id] = entry;
  }

  function updateToolResult(id, result, error) {
    const entry = entries[id];
    if (!entry) return;

    entry.classList.remove('running');

    const status = entry.querySelector('.tool-status');
    if (error) {
      status.className = 'tool-status error';
      status.textContent = 'ERR';
    } else {
      status.className = 'tool-status done';
      status.textContent = 'OK';
    }

    const body = entry.querySelector('.tool-body');
    const output = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
    body.innerHTML += `\n\n<strong>Result:</strong>\n${escapeHtml(output)}`;
  }

  function addThinking(text) {
    const entry = document.createElement('div');
    entry.className = 'thinking-entry';
    entry.textContent = text;
    log.prepend(entry);
  }

  function toggle(id) {
    const body = document.getElementById(`tool-body-${id}`);
    if (body) body.classList.toggle('open');
  }

  function getToolCount() {
    return toolCount;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { addToolCall, updateToolResult, addThinking, toggle, setPhase, getToolCount };
})();
