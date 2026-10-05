/* Saqlash: localStorage + muddat (oxirgi harakatdan keyin 30 daqiqa).
 * Backend yo‘q — ma’lumot faqat shu brauzerda qoladi. */
(function () {
  'use strict';
  const KEY = 'kriptolab.v1';
  const TTL = 30 * 60 * 1000; // 30 daqiqa (talab: kamida 20)

  const defaults = () => ({
    section: 'home',
    hero: { text: 'cybersecurity', key: null, iv: null },
    aes: { text: 'Symmetric encryption example', keySize: 32, key: null, iv: null, block: 0, step: 0, focus: 0 },
    rsa: { p: 61, q: 53, e: 17, msg: 'Salom', step: 0, sigMsg: '100 so‘m o‘tkazilsin', sigRecv: '100 so‘m o‘tkazilsin', realMsg: 'Public-key encryption example', realKeys: null },
    sha: { text: 'cybersecurity', block: 0, round: 0, wSel: 16, avA: 'cybersecurity', avB: 'Cybersecurity', bfWord: 'kalt' },
    hybrid: { msg: 'Ertaga soat 9:00 da uchrashamiz' },
    lab: { variant: null, name: '', group: '', answers: {}, checked: {}, results: {}, analysis: '', analysisChecked: false },
    quiz: { answers: {} },
    visited: {},
  });

  function merge(base, extra) {
    if (!extra || typeof extra !== 'object') return base;
    for (const k of Object.keys(extra)) {
      const v = extra[k];
      if (v && typeof v === 'object' && !Array.isArray(v) && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])) merge(base[k], v);
      else base[k] = v;
    }
    return base;
  }

  let state = defaults();
  let savedAt = 0;
  let restore = { status: 'new', ago: 0 };
  let storageOk = true;

  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const obj = JSON.parse(raw);
      const age = Date.now() - (obj.savedAt || 0);
      if (age <= TTL) {
        state = merge(defaults(), obj.data);
        savedAt = obj.savedAt;
        restore = { status: 'restored', ago: age };
      } else {
        localStorage.removeItem(KEY);
        restore = { status: 'expired', ago: age };
      }
    }
  } catch (e) { storageOk = false; }

  const listeners = [];
  let timer = null;

  function writeNow() {
    timer = null;
    savedAt = Date.now();
    try { localStorage.setItem(KEY, JSON.stringify({ savedAt, data: state })); storageOk = true; }
    catch (e) { storageOk = false; }
    listeners.forEach((fn) => fn(savedAt));
  }
  function save() {
    if (timer) clearTimeout(timer);
    listeners.forEach((fn) => fn(null));
    timer = setTimeout(writeNow, 250);
  }
  function reset() {
    try { localStorage.removeItem(KEY); } catch (e) {}
    state = defaults();
  }

  // Sahifada turganda ham muddatni yangilab turamiz
  setInterval(() => { if (document.visibilityState === 'visible') writeNow(); }, 60 * 1000);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') writeNow(); });
  window.addEventListener('pagehide', writeNow);

  window.Store = {
    get state() { return state; },
    save, reset, writeNow, TTL,
    get savedAt() { return savedAt; },
    get restore() { return restore; },
    get ok() { return storageOk; },
    onSave(fn) { listeners.push(fn); },
  };
})();
