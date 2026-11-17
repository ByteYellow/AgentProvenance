'use strict';
(() => {
  const zh = document.documentElement.lang === 'zh-CN';
  const text = (chinese, english) => zh ? chinese : english;
  const symbols = { minus:'M5 12h14', plus:'M5 12h14M12 5v14', fit:'M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5', close:'m6 6 12 12M18 6 6 18' };
  const button = (action, label) => `<button type="button" data-diagram-action="${action}" aria-label="${label}" title="${label}" class="${action==='close'?'diagram-close':''}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${symbols[action]}"/></svg></button>`;
  const dialog = document.createElement('dialog');
  dialog.className = 'diagram-dialog';
  dialog.setAttribute('aria-label', text('架构图', 'Architecture diagram'));
  dialog.innerHTML = `<header class="diagram-bar"><strong>${text('系统架构','System architecture')}</strong><div class="diagram-controls">${button('minus',text('缩小','Zoom out'))}<output aria-live="polite"></output>${button('plus',text('放大','Zoom in'))}${button('fit',text('适应宽度','Fit width'))}${button('close',text('关闭','Close'))}</div></header><div class="diagram-canvas" tabindex="0" aria-label="${text('架构图滚动区域','Scrollable architecture diagram')}"><img></div>`;
  document.body.append(dialog);
  const canvas = dialog.querySelector('.diagram-canvas');
  const image = canvas.querySelector('img');
  const output = dialog.querySelector('output');
  let scale = 1;
  let fitScale = 1;
  let trigger = null;

  function resize() {
    image.style.width = Math.round(image.naturalWidth * scale) + 'px';
    output.textContent = Math.round(scale * 100) + '%';
    dialog.querySelector('[data-diagram-action="minus"]').disabled = scale <= fitScale;
    dialog.querySelector('[data-diagram-action="plus"]').disabled = scale >= 2;
  }
  function fit() {
    const style = getComputedStyle(canvas);
    fitScale = Math.min(1, (canvas.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)) / image.naturalWidth);
    scale = fitScale;
    resize();
    canvas.scrollTo(0, 0);
  }
  document.querySelectorAll('[data-diagram-open]').forEach(control => control.addEventListener('click', async () => {
    trigger = control;
    const original = control.closest('.rendered-diagram').querySelector('img');
    image.src = original.src;
    image.alt = original.alt;
    await image.decode();
    dialog.showModal();
    fit();
    scale = Math.max(fitScale, 0.85);
    resize();
    canvas.scrollTo(Math.max(0, (canvas.scrollWidth - canvas.clientWidth) / 2), 0);
  }));
  dialog.addEventListener('click', event => {
    const control = event.target.closest('[data-diagram-action]');
    if (!control) return;
    const action = control.dataset.diagramAction;
    if (action === 'close') return dialog.close();
    if (action === 'fit') return fit();
    const before = scale;
    scale = Math.max(fitScale, Math.min(2, scale * (action === 'plus' ? 1.4 : 1 / 1.4)));
    const centerX = (canvas.scrollLeft + canvas.clientWidth / 2) / before;
    const centerY = (canvas.scrollTop + canvas.clientHeight / 2) / before;
    resize();
    canvas.scrollTo(centerX * scale - canvas.clientWidth / 2, centerY * scale - canvas.clientHeight / 2);
  });
  dialog.addEventListener('close', () => trigger?.focus({ preventScroll: true }));
  window.addEventListener('resize', () => { if (dialog.open) fit(); });
})();
