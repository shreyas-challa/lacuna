// Theme toggle — View Transition circular reveal with graceful fallback.

(() => {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;

  function apply(theme) {
    const root = document.documentElement;
    if (theme === 'light') root.classList.remove('dark');
    else root.classList.add('dark');
    try { localStorage.setItem('lacuna-theme', theme); } catch (e) { /* ignore */ }
    // Re-color the D3 graph to match the new palette.
    if (window.GraphViz && typeof GraphViz.restyle === 'function') GraphViz.restyle();
  }

  btn.addEventListener('click', () => {
    const isDark = document.documentElement.classList.contains('dark');
    const next = isDark ? 'light' : 'dark';

    if (!document.startViewTransition) { apply(next); return; }

    const r = btn.getBoundingClientRect();
    const x = r.left + r.width / 2;
    const y = r.top + r.height / 2;
    const end = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));

    const vt = document.startViewTransition(() => apply(next));
    vt.ready.then(() => {
      document.documentElement.animate(
        { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${end}px at ${x}px ${y}px)`] },
        { duration: 400, easing: 'ease-in-out', pseudoElement: '::view-transition-new(root)' }
      );
    });
  });
})();
