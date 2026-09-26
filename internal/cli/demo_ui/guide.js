'use strict';
const t = window.AgentProvI18n.t;
// Enhance rendered content locally; no network libraries or model calls.
document.querySelectorAll('.document pre > code').forEach(code => {
  const pre = code.parentElement;
  const wrapper = document.createElement('div');
  wrapper.className = 'code-block';
  const bar = document.createElement('div');
  bar.className = 'code-toolbar';
  const label = document.createElement('span');
  const language = [...code.classList].find(name => name.startsWith('language-'));
  label.textContent = language ? language.slice(9).toUpperCase() : t('TEXT');
  const button = document.createElement('button');
  button.type = 'button'; button.textContent = t('Copy'); button.setAttribute('aria-label', t('Copy code'));
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = t('Copied');
    } catch {
      const selection = window.getSelection();
      const range = document.createRange(); range.selectNodeContents(code);
      selection.removeAllRanges(); selection.addRange(range);
      button.textContent = t('Select & copy');
    }
    setTimeout(() => { button.textContent = t('Copy'); }, 1800);
  });
  bar.append(label, button); pre.before(wrapper); wrapper.append(bar, pre);
});
document.querySelectorAll('.document table').forEach(table => {
  const wrapper = document.createElement('div'); wrapper.className = 'table-scroll';
  wrapper.tabIndex = 0; wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', t('Scrollable table'));
  table.before(wrapper); wrapper.append(table);
});
document.querySelectorAll('.document a[href]').forEach(link => {
  if (link.origin !== location.origin) { link.target = '_blank'; link.rel = 'noopener noreferrer'; }
});
const pageLinks = [...document.querySelectorAll('.page-nav a')];
const headingObserver = new IntersectionObserver(entries => {
  const heading = entries.find(entry => entry.isIntersecting);
  if (!heading) return;
  pageLinks.forEach(link => link.classList.toggle('active', decodeURIComponent(link.hash.slice(1)) === heading.target.id));
}, {rootMargin: '-80px 0px -65% 0px'});
document.querySelectorAll('.document h2[id]').forEach(heading => headingObserver.observe(heading));
if (matchMedia('(max-width: 700px)').matches) document.querySelector('.guide-nav').open = false;
