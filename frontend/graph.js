// D3.js force-directed attack graph — Phosphor theme

const GraphViz = (() => {
  const NODE_COLORS = {
    machine: '#e8a634',
    service: '#22c55e',
    user: '#eab308',
    vulnerability: '#f97316',
    root: '#ef4444',
  };

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
  let currentNodes = [];
  let currentLinks = [];
  let nodeCount = 0;

  function init() {
    svg = d3.select('#graph-svg');
    const rect = svg.node().getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;

    defs = svg.append('defs');

    // Dot grid pattern
    const pattern = defs.append('pattern')
      .attr('id', 'dot-grid')
      .attr('width', 20)
      .attr('height', 20)
      .attr('patternUnits', 'userSpaceOnUse');
    pattern.append('circle')
      .attr('cx', 10)
      .attr('cy', 10)
      .attr('r', 0.8)
      .attr('fill', '#1a1a1a');

    // Background rect with dot grid
    svg.insert('rect', ':first-child')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('fill', '#0c0c0c');
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
      .attr('fill', '#2a2a2a');

    // Glow filters per type
    Object.entries(NODE_COLORS).forEach(([type, color]) => {
      const filter = defs.append('filter')
        .attr('id', `glow-${type}`)
        .attr('x', '-50%').attr('y', '-50%')
        .attr('width', '200%').attr('height', '200%');
      filter.append('feGaussianBlur')
        .attr('in', 'SourceGraphic')
        .attr('stdDeviation', '3')
        .attr('result', 'blur');
      filter.append('feFlood')
        .attr('flood-color', color)
        .attr('flood-opacity', '0.4')
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
      .on('zoom', (event) => {
        container.attr('transform', event.transform);
      });
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

    // Outer glow ring
    nodeEnter.append('circle')
      .attr('class', 'node-glow')
      .attr('r', 0)
      .attr('stroke', d => NODE_COLORS[d.type] || '#e8a634')
      .attr('stroke-width', 1.5)
      .attr('filter', d => `url(#glow-${d.type || 'machine'})`)
      .transition().duration(500)
      .ease(d3.easeElasticOut.amplitude(1).period(0.4))
      .attr('r', GLOW_RADIUS);

    // Inner filled circle
    nodeEnter.append('circle')
      .attr('class', 'node-fill')
      .attr('r', 0)
      .attr('fill', d => NODE_COLORS[d.type] || '#e8a634')
      .attr('stroke', '#0c0c0c')
      .attr('stroke-width', 2)
      .transition().duration(500)
      .ease(d3.easeElasticOut.amplitude(1).period(0.4))
      .attr('r', NODE_RADIUS);

    // Type icon letter
    nodeEnter.append('text')
      .attr('class', 'node-icon')
      .text(d => NODE_ICONS[d.type] || '?')
      .attr('opacity', 0)
      .transition().delay(200).duration(300)
      .attr('opacity', 1);

    // Update existing node colors
    nodeG.select('.node-glow')
      .attr('stroke', d => NODE_COLORS[d.type] || '#e8a634')
      .attr('filter', d => `url(#glow-${d.type || 'machine'})`);
    nodeG.select('.node-fill')
      .attr('fill', d => NODE_COLORS[d.type] || '#e8a634');
    nodeG.select('.node-icon')
      .text(d => NODE_ICONS[d.type] || '?');

    // Labels
    const label = labelGroup.selectAll('text').data(currentNodes, d => d.id);
    label.exit().remove();
    label.enter().append('text')
      .attr('class', 'node-label')
      .text(d => d.label || d.id);
    label.text(d => d.label || d.id);

    // Update node count
    nodeCount = currentNodes.length;

    // Restart simulation
    simulation.nodes(currentNodes);
    simulation.force('link').links(currentLinks);
    simulation.alpha(0.3).restart();
  }

  function getNodeCount() {
    return nodeCount;
  }

  function getNodes() {
    return currentNodes;
  }

  function drag(sim) {
    return d3.drag()
      .on('start', (event, d) => {
        if (!event.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) sim.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });
  }

  return { init, update, getNodeCount, getNodes };
})();
