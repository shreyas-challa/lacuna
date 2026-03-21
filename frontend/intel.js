// Intel panel — strategy view + structured discovery listing

const Intel = (() => {
  const container = document.getElementById('intel-content');
  const strategyContainer = document.getElementById('strategy-section');

  const SECTIONS = {
    machine: 'Hosts',
    service: 'Services',
    vulnerability: 'Vulnerabilities',
    user: 'Credentials / Users',
    root: 'Root / Flags',
  };

  function updateStrategy(strategy, phase) {
    if (!strategyContainer) return;

    const phaseLabel = (phase || 'unknown').toUpperCase();
    let html = `<div class="strategy-panel">`;
    html += `<div class="strategy-header">`;
    html += `<span class="strategy-title">STRATEGY</span>`;
    html += `<span class="strategy-phase">${escapeHtml(phaseLabel)}</span>`;
    html += `</div>`;
    html += `<div class="strategy-body">${escapeHtml(strategy)}</div>`;
    html += `</div>`;

    strategyContainer.innerHTML = html;
  }

  function update(nodes) {
    if (!nodes || !nodes.length) return;

    // Group by type
    const groups = {};
    nodes.forEach(n => {
      const type = n.type || 'machine';
      if (!groups[type]) groups[type] = [];
      // Deduplicate by id
      if (!groups[type].find(x => x.id === n.id)) {
        groups[type].push(n);
      }
    });

    let html = '';

    // Render in defined order
    for (const [type, title] of Object.entries(SECTIONS)) {
      const items = groups[type];
      if (!items || !items.length) continue;

      html += `<div class="intel-section">`;
      html += `<div class="intel-section-header">${title} (${items.length})</div>`;

      items.forEach(item => {
        const label = escapeHtml(item.label || item.id);
        html += `<div class="intel-item">`;
        html += `<span class="intel-type-badge ${type}">${type.slice(0, 4).toUpperCase()}</span>`;
        html += `<span class="intel-item-label">${label}</span>`;
        html += `</div>`;
      });

      html += `</div>`;
    }

    // Any unknown types
    for (const [type, items] of Object.entries(groups)) {
      if (SECTIONS[type]) continue;
      html += `<div class="intel-section">`;
      html += `<div class="intel-section-header">${escapeHtml(type)} (${items.length})</div>`;
      items.forEach(item => {
        const label = escapeHtml(item.label || item.id);
        html += `<div class="intel-item">`;
        html += `<span class="intel-type-badge">${type.slice(0, 4).toUpperCase()}</span>`;
        html += `<span class="intel-item-label">${label}</span>`;
        html += `</div>`;
      });
      html += `</div>`;
    }

    container.innerHTML = html;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { update, updateStrategy };
})();
