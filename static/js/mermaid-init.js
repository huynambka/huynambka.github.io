document.addEventListener('DOMContentLoaded', async function () {
  if (typeof mermaid === 'undefined') return;

  mermaid.initialize({
    startOnLoad: false,
    securityLevel: 'loose',
  });

  await mermaid.run({ querySelector: '.mermaid' });

  // After mermaid renders, remove its fixed inline dimensions so CSS can
  // scale the SVG properly (width: 100%, height: auto via viewBox ratio).
  document.querySelectorAll('.mermaid svg').forEach(function (svg) {
    svg.removeAttribute('height');
    svg.removeAttribute('width');
    svg.style.removeProperty('max-width');
    svg.style.removeProperty('height');
  });
});
