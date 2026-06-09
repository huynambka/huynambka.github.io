document.addEventListener('DOMContentLoaded', async function () {
  if (typeof mermaid === 'undefined') return;

  mermaid.initialize({
    startOnLoad: false,
    securityLevel: 'loose',
  });

  await mermaid.run({ querySelector: '.mermaid' });

  // Size each diagram from its viewBox, then allow it to shrink to fit the
  // content column. This avoids tiny SVGs from theme CSS and avoids stretching
  // narrow diagrams to full width.
  document.querySelectorAll('.mermaid svg').forEach(function (svg) {
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
  });
});
