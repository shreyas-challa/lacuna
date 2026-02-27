// D3.js force-directed attack graph

const GraphViz = (() => {
  const NODE_COLORS = {
    machine: '#3b82f6',
    service: '#22c55e',
    user: '#eab308',
    vulnerability: '#f97316',
    root: '#ef4444',
  };

  const NODE_RADIUS = 18;

  let svg, container, simulation;
  let nodeGroup, linkGroup, labelGroup, linkLabelGroup;
  let currentNodes = [];
  let currentLinks = [];

  function init() {
    svg = d3.select('#graph-svg');
    const rect = svg.node().getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        container.attr('transform', event.transform);
      });

    svg.call(zoom);

    container = svg.append('g');

    // Arrow marker
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', NODE_RADIUS + 10)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#2a3550');

    linkGroup = container.append('g').attr('class', 'links');
    linkLabelGroup = container.append('g').attr('class', 'link-labels');
    nodeGroup = container.append('g').attr('class', 'nodes');
    labelGroup = container.append('g').attr('class', 'labels');

    simulation = d3.forceSimulation()
      .force('link', d3.forceLink().id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(NODE_RADIUS + 10))
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

    nodeGroup.selectAll('circle')
      .attr('cx', d => d.x)
      .attr('cy', d => d.y);

    labelGroup.selectAll('text')
      .attr('x', d => d.x)
      .attr('y', d => d.y + NODE_RADIUS + 14);
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

    // Nodes
    const node = nodeGroup.selectAll('circle').data(currentNodes, d => d.id);
    node.exit().remove();
    const nodeEnter = node.enter().append('circle')
      .attr('r', 0)
      .attr('fill', d => NODE_COLORS[d.type] || '#3b82f6')
      .attr('stroke', '#0a0e17')
      .attr('stroke-width', 2)
      .attr('cursor', 'grab')
      .call(drag(simulation));

    // Animate entrance
    nodeEnter.transition().duration(400)
      .attr('r', NODE_RADIUS);

    // Update colors on existing nodes
    node.attr('fill', d => NODE_COLORS[d.type] || '#3b82f6');

    // Labels
    const label = labelGroup.selectAll('text').data(currentNodes, d => d.id);
    label.exit().remove();
    label.enter().append('text')
      .attr('class', 'node-label')
      .text(d => d.label || d.id);
    label.text(d => d.label || d.id);

    // Restart simulation
    simulation.nodes(currentNodes);
    simulation.force('link').links(currentLinks);
    simulation.alpha(0.3).restart();
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

  return { init, update };
})();
