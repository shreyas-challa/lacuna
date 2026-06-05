// D3.js force-directed attack graph — palette driven by CSS design tokens.

const GraphViz = (() => {
  const TYPES = ['machine', 'service', 'user', 'vulnerability', 'root'];

  const NODE_ICONS = {
    machine: 'M',
    service: 'S',
    user: 'U',
    vulnerability: 'V',
    root: 'R',
  };

  const NODE_RADIUS = 16;
  const GLOW_RADIUS = 22;

  let svg, defs, container, simulation;
  let nodeGroup, linkGroup, labelGroup, linkLabelGroup;
  let bgRect, dotCircle;
  let currentNodes = [];
  let currentLinks = [];
  let nodeCount = 0;
  const filterFloods = {};

  // Read live values from the CSS custom properties so the graph
  // always matches the active (light/dark) theme.
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function nodeColors() {
    return {
      machine: cssVar('--viz-machine'),
      service: cssVar('--viz-service'),
      user: cssVar('--viz-user'),
      vulnerability: cssVar('--viz-vuln'),
      root: cssVar('--viz-root'),
    };
  }
  function colorFor(type, colors) {
    return (colors || nodeColors())[type] || cssVar('--viz-machine');
  }

  function init() {
    svg = d3.select('#graph-svg');
    const rect = svg.node().getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;

    defs = svg.append('defs');

    // Dot grid pattern
    const pattern = defs.append('pattern')
      .attr('id', 'dot-grid')
      .attr('width', 22)
      .attr('height', 22)
      .attr('patternUnits', 'userSpaceOnUse');
    dotCircle = pattern.append('circle')
      .attr('cx', 11)
      .attr('cy', 11)
      .attr('r', 0.9)
      .attr('fill', cssVar('--graph-dot'));

    // Background
    bgRect = svg.insert('rect', ':first-child')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('fill', cssVar('--graph-bg'));
    svg.insert('rect', 'g')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('fill', 'url(#dot-grid)');

    // Arrow marker
    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', GLOW_RADIUS + 8)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', cssVar('--graph-link'));

    // Glow filters per type
    const colors = nodeColors();
    TYPES.forEach((type) => {
      const filter = defs.append('filter')
        .attr('id', `glow-${type}`)
        .attr('x', '-50%').attr('y', '-50%')
        .attr('width', '200%').attr('height', '200%');
      filter.append('feGaussianBlur')
        .attr('in', 'SourceGraphic')
        .attr('stdDeviation', '3')
        .attr('result', 'blur');
      filterFloods[type] = filter.append('feFlood')
        .attr('flood-color', colors[type])
        .attr('flood-opacity', '0.45')
        .attr('result', 'color');
      filter.append('feComposite')
        .attr('in', 'color')
        .attr('in2', 'blur')
        .attr('operator', 'in')
        .attr('result', 'glow');
      const merge = filter.append('feMerge');
      merge.append('feMergeNode').attr('in', 'glow');
      merge.append('feMergeNode').attr('in', 'SourceGraphic');
    });

    // Zoom
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => container.attr('transform', event.transform));
    svg.call(zoom);

    container = svg.append('g');
    linkGroup = container.append('g').attr('class', 'links');
    linkLabelGroup = container.append('g').attr('class', 'link-labels');
    nodeGroup = container.append('g').attr('class', 'nodes');
    labelGroup = container.append('g').attr('class', 'labels');

    simulation = d3.forceSimulation()
      .force('link', d3.forceLink().id(d => d.id).distance(130))
      .force('charge', d3.forceManyBody().strength(-450))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(GLOW_RADIUS + 8))
      .on('tick', ticked);

    simulation.stop();
  }

  function ticked() {
    linkGroup.selectAll('line')
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    linkLabelGroup.selectAll('text')
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2);

    nodeGroup.selectAll('g.node-group')
      .attr('transform', d => `translate(${d.x},${d.y})`);

    labelGroup.selectAll('text')
      .attr('x', d => d.x)
      .attr('y', d => d.y + GLOW_RADIUS + 12);
  }

  function update(nodes, edges) {
    const colors = nodeColors();
    const nodeStroke = cssVar('--node-stroke');

    // Preserve existing positions
    const posMap = {};
    currentNodes.forEach(n => { posMap[n.id] = { x: n.x, y: n.y, vx: n.vx, vy: n.vy }; });

    currentNodes = nodes.map(n => {
      const existing = posMap[n.id];
      return existing ? { ...n, ...existing } : { ...n };
    });

    currentLinks = edges.map(e => ({ ...e, source: e.source, target: e.target }));

    // Links
    const link = linkGroup.selectAll('line').data(currentLinks, d => d.source + '-' + d.target);
    link.exit().remove();
    link.enter().append('line')
      .attr('class', 'graph-link')
      .attr('marker-end', 'url(#arrow)');

    // Link labels
    const linkLabel = linkLabelGroup.selectAll('text').data(currentLinks, d => d.source + '-' + d.target);
    linkLabel.exit().remove();
    linkLabel.enter().append('text')
      .attr('class', 'graph-link-label')
      .text(d => d.label || '');

    // Node groups
    const nodeG = nodeGroup.selectAll('g.node-group').data(currentNodes, d => d.id);
    nodeG.exit().remove();

    const nodeEnter = nodeG.enter().append('g')
      .attr('class', 'node-group')
      .attr('cursor', 'grab')
      .call(drag(simulation));

    nodeEnter.append('circle')
      .attr('class', 'node-glow')
      .attr('r', 0)
      .attr('stroke', d => colorFor(d.type, colors))
      .attr('stroke-width', 1.5)
      .attr('filter', d => `url(#glow-${d.type || 'machine'})`)
      .transition().duration(500)
      .ease(d3.easeElasticOut.amplitude(1).period(0.4))
      .attr('r', GLOW_RADIUS);

    nodeEnter.append('circle')
      .attr('class', 'node-fill')
      .attr('r', 0)
      .attr('fill', d => colorFor(d.type, colors))
      .attr('stroke', nodeStroke)
      .attr('stroke-width', 2)
      .transition().duration(500)
      .ease(d3.easeElasticOut.amplitude(1).period(0.4))
      .attr('r', NODE_RADIUS);

    nodeEnter.append('text')
      .attr('class', 'node-icon')
      .text(d => NODE_ICONS[d.type] || '?')
      .attr('opacity', 0)
      .transition().delay(200).duration(300)
      .attr('opacity', 1);

    // Update existing node colors
    nodeG.select('.node-glow')
      .attr('stroke', d => colorFor(d.type, colors))
      .attr('filter', d => `url(#glow-${d.type || 'machine'})`);
    nodeG.select('.node-fill')
      .attr('fill', d => colorFor(d.type, colors))
      .attr('stroke', nodeStroke);
    nodeG.select('.node-icon')
      .text(d => NODE_ICONS[d.type] || '?');

    // Labels
    const label = labelGroup.selectAll('text').data(currentNodes, d => d.id);
    label.exit().remove();
    label.enter().append('text')
      .attr('class', 'node-label')
      .text(d => d.label || d.id);
    label.text(d => d.label || d.id);

    nodeCount = currentNodes.length;

    simulation.nodes(currentNodes);
    simulation.force('link').links(currentLinks);
    simulation.alpha(0.3).restart();
  }

  // Re-read the CSS tokens and recolor everything (called on theme toggle).
  function restyle() {
    if (!svg) return;
    const colors = nodeColors();
    const nodeStroke = cssVar('--node-stroke');

    if (bgRect) bgRect.attr('fill', cssVar('--graph-bg'));
    if (dotCircle) dotCircle.attr('fill', cssVar('--graph-dot'));
    defs.select('#arrow path').attr('fill', cssVar('--graph-link'));

    TYPES.forEach((type) => {
      if (filterFloods[type]) filterFloods[type].attr('flood-color', colors[type]);
    });

    nodeGroup.selectAll('g.node-group').select('.node-glow')
      .attr('stroke', d => colorFor(d.type, colors));
    nodeGroup.selectAll('g.node-group').select('.node-fill')
      .attr('fill', d => colorFor(d.type, colors))
      .attr('stroke', nodeStroke);
  }

  function getNodeCount() { return nodeCount; }
  function getNodes() { return currentNodes; }

  function drag(sim) {
    return d3.drag()
      .on('start', (event, d) => {
        if (!event.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x; d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) sim.alphaTarget(0);
        d.fx = null; d.fy = null;
      });
  }

  return { init, update, restyle, getNodeCount, getNodes };
})();
