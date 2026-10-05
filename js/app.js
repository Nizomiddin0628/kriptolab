/* Ilova: marshrutlash, mavzu, saqlash ko‘rsatkichi, progress, hisobot */
(function () {
  'use strict';
  const { $, $$, toast, download, copy } = UI;
  const PAGES = ['home', 'history', 'aes', 'rsa', 'sha', 'hybrid', 'lab', 'quiz', 'report'];
  const HOOKS = { home: () => window.Home, aes: () => window.AESViz, rsa: () => window.RSAViz, sha: () => window.SHAViz };
  let current = null;
  let pendingAfter = null;

  function show(page) {
    if (!PAGES.includes(page)) page = 'home';
    if (current && current !== page) { const h = HOOKS[current] && HOOKS[current](); h && h.onHide && h.onHide(); }
    $$('.page').forEach((p) => p.classList.toggle('active', p.dataset.page === page));
    $$('[data-nav]').forEach((a) => (a.dataset.nav === page ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
    const nav = $(`[data-nav="${page}"]`);
    if (nav && window.innerWidth <= 900) nav.scrollIntoView({ inline: 'center', block: 'nearest' });
    const prev = current;
    current = page;
    Store.state.section = page;
    Store.state.visited[page] = true;
    Store.save();
    const h = HOOKS[page] && HOOKS[page]();
    if (h && h.onShow) h.onShow();
    if (page === 'report') renderReport();
    if (page === 'lab' && prev && prev !== 'lab') Lab.rerender();
    if (pendingAfter) { const fn = pendingAfter; pendingAfter = null; setTimeout(fn, 60); }
    else if (prev !== page) window.scrollTo(0, 0);
  }
  function onHash() { show((location.hash || '#' + (Store.state.section || 'home')).slice(1)); }

  /* boshqa bo‘limdan animatsiyaga o‘tish */
  function go(page, after) {
    pendingAfter = after || null;
    if (location.hash === '#' + page) { show(page); }
    else location.hash = page;
  }
  function focusEl(sel) {
    const el = $(sel);
    if (!el) return;
    const panel = el.closest('.panel') || el;
    panel.scrollIntoView({ behavior: UI.reduced() ? 'auto' : 'smooth', block: 'start' });
    panel.animate && panel.animate([{ boxShadow: '0 0 0 0 var(--hot)' }, { boxShadow: '0 0 0 6px var(--hot)' }, { boxShadow: '0 0 0 0 transparent' }], { duration: 1600, easing: 'ease-out' });
  }

  /* mavzu */
  function applyTheme(t) {
    if (t) document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem('kriptolab.theme', JSON.stringify(t)); } catch (e) {}
  }
  function currentTheme() {
    const t = document.documentElement.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  /* saqlash ko‘rsatkichi */
  const fmt = (ts) => new Date(ts).toLocaleTimeString('uz-UZ', { hour: '2-digit', minute: '2-digit' });
  function paintSave(ts) {
    const chip = $('#saveChip');
    if (!Store.ok) { chip.classList.remove('saving'); $('#saveText').textContent = 'Saqlash o‘chirilgan (brauzer ruxsat bermadi)'; return; }
    if (ts === null) { chip.classList.add('saving'); return; }
    chip.classList.remove('saving');
    $('#saveText').innerHTML = `<span class="txt-long">Saqlangan, </span>${fmt(ts + Store.TTL)} gacha`;
    chip.title = `Oxirgi saqlash: ${fmt(ts)}. Sahifani yopsangiz ham, ${Store.TTL / 60000} daqiqa ichida qaytsangiz ishingiz joyida bo‘ladi.`;
  }

  function updateProgress() {
    const n = Lab.doneCount();
    $('#navProgText').textContent = `${n} / 4`;
    $('#navProgBar').style.width = (n / 4) * 100 + '%';
    $('[data-nav="lab"]').classList.toggle('done', n === 4);
    const q = Object.keys(Store.state.quiz.answers).length;
    $('[data-nav="quiz"]').classList.toggle('done', q === 10);
  }

  function renderReport() { $('#reportBox').textContent = Lab.reportText(); }

  function init() {
    // modullar
    [Home, AESViz, RSAViz, SHAViz, Hybrid, Lab, Quiz].forEach((m) => { try { m.init(); } catch (e) { console.error(e); } });

    $('#themeBtn').addEventListener('click', () => applyTheme(currentTheme() === 'dark' ? 'light' : 'dark'));
    $('#resetBtn').addEventListener('click', () => {
      if (!confirm('Barcha natijalar, javoblar va kalitlar o‘chiriladi. Davom etasizmi?')) return;
      Store.reset();
      try { localStorage.removeItem('kriptolab.v1'); } catch (e) {}
      location.hash = 'home';
      location.reload();
    });
    $('#repDownload').addEventListener('click', () => {
      const s = Store.state.lab;
      const name = `2-amaliy-ish_variant-${s.variant || 'x'}${s.name ? '_' + s.name.replace(/\s+/g, '-') : ''}.txt`;
      download(name, Lab.reportText());
    });
    $('#repPrint').addEventListener('click', () => { renderReport(); window.print(); });
    $('#repCopy').addEventListener('click', () => copy(Lab.reportText()));

    Store.onSave(paintSave);
    if (Store.savedAt) paintSave(Store.savedAt); else Store.save();

    window.addEventListener('hashchange', onHash);
    onHash();
    updateProgress();

    const r = Store.restore;
    if (r.status === 'restored') toast(`Ishingiz tiklandi — ${Math.max(1, Math.round(r.ago / 60000))} daqiqa oldin saqlangan`, 3600);
    else if (r.status === 'expired') toast(`Oldingi sessiya ${Store.TTL / 60000} daqiqadan oshib ketgani uchun tozalandi`, 4200);
  }

  window.App = { go, focusEl, updateProgress, show };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
