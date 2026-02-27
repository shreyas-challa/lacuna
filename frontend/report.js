// Markdown report renderer

const Report = (() => {
  const container = document.getElementById('report-content');

  function update(markdown) {
    container.innerHTML = marked.parse(markdown);
  }

  return { update };
})();
