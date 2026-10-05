/* Umumiy UI yordamchilari */
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const reduced = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let toastT;
  function toast(msg, ms) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastT);
    toastT = setTimeout(() => t.classList.remove('show'), ms || 2600);
  }

  /* Belgilarni “aralashtirib” keyin joyiga qo‘yish animatsiyasi */
  const scrambleTimers = new WeakMap();
  function scramble(el, text, opts) {
    opts = opts || {};
    const pool = opts.pool || '0123456789abcdef';
    if (reduced()) { el.textContent = text; return; }
    const prev = scrambleTimers.get(el);
    if (prev) cancelAnimationFrame(prev);
    const dur = opts.duration || 600;
    const start = performance.now();
    const tick = (now) => {
      const p = Math.min(1, (now - start) / dur);
      const fixed = Math.floor(p * text.length);
      let s = text.slice(0, fixed);
      for (let i = fixed; i < text.length; i++) s += text[i] === ' ' ? ' ' : pool[(Math.random() * pool.length) | 0];
      el.textContent = s;
      if (p < 1) scrambleTimers.set(el, requestAnimationFrame(tick));
      else el.textContent = text;
    };
    scrambleTimers.set(el, requestAnimationFrame(tick));
  }

  function download(name, text) {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast('Nusxa olindi'); }
    catch (e) { toast('Nusxa olib bo‘lmadi — matnni qo‘lda belgilang'); }
  }

  /* Python b'...' ko‘rinishi */
  function pyBytes(str) {
    const bytes = K.enc.encode(str);
    let s = '';
    for (const b of bytes) {
      if (b === 0x27) s += "\\'";
      else if (b === 0x5c) s += '\\\\';
      else if (b >= 0x20 && b < 0x7f) s += String.fromCharCode(b);
      else s += '\\x' + K.hex2(b);
    }
    return "b'" + s + "'";
  }

  function hasSubtle() { return !!(window.crypto && window.crypto.subtle); }

  /* Oddiy bosqichli ijrochi (play/pause) */
  function Player(opts) {
    let timer = null;
    const api = {
      get playing() { return !!timer; },
      play() {
        if (timer) return;
        opts.onState && opts.onState(true);
        const loop = () => {
          if (!opts.next()) { api.pause(); return; }
          timer = setTimeout(loop, opts.interval());
        };
        timer = setTimeout(loop, 60);
      },
      pause() { if (timer) clearTimeout(timer); timer = null; opts.onState && opts.onState(false); },
      toggle() { timer ? api.pause() : api.play(); },
    };
    return api;
  }

  window.UI = { $, $$, esc, debounce, sleep, toast, scramble, download, copy, pyBytes, hasSubtle, Player, reduced };
})();
