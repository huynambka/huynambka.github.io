document.addEventListener('DOMContentLoaded', function () {
  if (typeof mermaid === 'undefined') return;

  var renderQueue = Promise.resolve();

  function isDarkMode() {
    var darkStyle = document.getElementById('darkModeStyle');
    return Boolean(darkStyle) && darkStyle.disabled === false;
  }

  function getMermaidConfig() {
    var darkMode = isDarkMode();

    return {
      startOnLoad: false,
      securityLevel: 'loose',
      theme: 'base',
      fontFamily: '"Fira Sans", sans-serif',
      themeVariables: darkMode
        ? {
            darkMode: true,
            background: '#202124',
            primaryColor: '#2d3748',
            primaryTextColor: '#f8fafc',
            primaryBorderColor: '#50fa7b',
            lineColor: '#9aa0a6',
            textColor: '#e5e7eb',
            tertiaryColor: '#374151',
            noteBkgColor: '#1f2937',
            noteTextColor: '#f8fafc',
          }
        : {
            darkMode: false,
            background: '#ffffff',
            primaryColor: '#ececff',
            primaryTextColor: '#232333',
            primaryBorderColor: '#9370db',
            lineColor: '#4b5563',
            textColor: '#232333',
            tertiaryColor: '#f5f3ff',
            noteBkgColor: '#fff5ad',
            noteTextColor: '#232333',
          },
    };
  }

  function normalizeMermaidSvg(svg) {
    var viewBox = svg.getAttribute('viewBox');
    var intrinsicWidth = null;

    if (viewBox) {
      var parts = viewBox.trim().split(/\s+/);
      if (parts.length === 4) {
        var parsedWidth = parseFloat(parts[2]);
        if (!Number.isNaN(parsedWidth) && parsedWidth > 0) {
          intrinsicWidth = parsedWidth + 'px';
        }
      }
    }

    svg.removeAttribute('height');
    svg.removeAttribute('width');

    if (intrinsicWidth) {
      svg.style.setProperty('width', intrinsicWidth, 'important');
    }

    svg.style.setProperty('max-width', '100%', 'important');
    svg.style.setProperty('max-height', 'none', 'important');
    svg.style.setProperty('height', 'auto', 'important');
  }

  async function renderMermaidDiagrams() {
    var containers = Array.from(document.querySelectorAll('.mermaid'));

    if (containers.length === 0) return;

    mermaid.initialize(getMermaidConfig());

    containers.forEach(function (container) {
      var source = container.dataset.mermaidSource;

      if (!source) {
        source = container.textContent.trim();
        container.dataset.mermaidSource = source;
      }

      container.removeAttribute('data-processed');
      container.textContent = source;
    });

    await mermaid.run({ querySelector: '.mermaid' });

    document.querySelectorAll('.mermaid svg').forEach(normalizeMermaidSvg);
  }

  function scheduleMermaidRender() {
    renderQueue = renderQueue
      .then(renderMermaidDiagrams)
      .catch(function (error) {
        console.error('Failed to render Mermaid diagrams:', error);
      });

    return renderQueue;
  }

  scheduleMermaidRender();
  window.addEventListener('themechange', scheduleMermaidRender);
});
