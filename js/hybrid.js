/* Gibrid tizim: RSA + AES + SHA-256 haqiqiy kalitlar bilan, qadamma-qadam */
(function () {
  'use strict';
  const { $, esc, toast, hasSubtle } = UI;
  const S = () => Store.state.hybrid;
  let step = -1;
  let ctx = {};
  let busy = false;

  // [tomon, sarlavha, bajaruvchi funksiya] — tomon: 'L' Bobur, 'R' Aziza, 'W' tarmoq
  const STEPS = [
    ['R', 'Aziza RSA-2048 kalit juftligini yaratadi va ochiq kalitini Boburga beradi', async () => {
      const prev = RSAViz.Real.keys; // RSA bo‘limidagi kalitlarga tegmaymiz
      const k = await RSAViz.Real.generate();
      ctx.az = RSAViz.Real.keys;
      await RSAViz.Real.generate();
      ctx.bob = RSAViz.Real.keys;
      RSAViz.Real.keys = prev;
      return `Aziza n = ${RSAViz.Real.modulusHex(k.pub).slice(0, 40)}…  (Bobur ham imzo uchun o‘z juftligini yaratdi)`;
    }],
    ['L', 'Bobur tasodifiy AES-256 kalit K va IV yaratadi', async () => {
      ctx.K = K.randBytes(32); ctx.iv = K.randBytes(16);
      return `K = ${K.toHex(ctx.K)}\nIV = ${K.toHex(ctx.iv)}`;
    }],
    ['L', 'Xabarni AES-256-CBC bilan shifrlaydi (tez, istalgan hajm)', async () => {
      ctx.msg = S().msg;
      ctx.ct = K.AES.cbcEncrypt(K.enc.encode(ctx.msg), ctx.K, ctx.iv).ct;
      return `C = ${K.toHex(ctx.ct)}`;
    }],
    ['L', 'K ni Azizaning OCHIQ kaliti bilan RSA-OAEP orqali “o‘raydi”', async () => {
      ctx.wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, ctx.az.encPub, ctx.K));
      return `RSA(K) = ${K.toHex(ctx.wrapped).slice(0, 96)}… (256 bayt)`;
    }],
    ['L', 'SHA-256(xabar) ni o‘zining YOPIQ kaliti bilan imzolaydi (PSS)', async () => {
      ctx.hash = K.SHA.sha256Hex(ctx.msg);
      ctx.sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 222 }, ctx.bob.sigPriv, K.enc.encode(ctx.msg)));
      return `SHA-256 = ${ctx.hash}\nimzo = ${K.toHex(ctx.sig).slice(0, 64)}…`;
    }],
    ['W', 'Tarmoq orqali faqat { C, IV, RSA(K), imzo } ketadi — xabar ham, K ham ochiq ko‘rinmaydi', async () => ''],
    ['R', 'Aziza RSA(K) ni o‘zining YOPIQ kaliti bilan ochib, K ni oladi', async () => {
      ctx.K2 = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, ctx.az.encPriv, ctx.wrapped));
      return `K = ${K.toHex(ctx.K2)}  ${K.toHex(ctx.K2) === K.toHex(ctx.K) ? '✓ Boburniki bilan bir xil' : '✗'}`;
    }],
    ['R', 'C ni K bilan AES orqali ochadi', async () => {
      ctx.pt = K.dec.decode(K.AES.cbcDecrypt(ctx.ct, ctx.K2, ctx.iv));
      return `xabar = "${ctx.pt}"`;
    }],
    ['R', 'SHA-256 ni o‘zi hisoblab, imzoni Boburning OCHIQ kaliti bilan tekshiradi', async () => {
      const ok = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 222 }, ctx.bob.sigPub, ctx.sig, K.enc.encode(ctx.pt));
      return `SHA-256 = ${K.SHA.sha256Hex(ctx.pt)}\n${ok ? '✓ Imzo to‘g‘ri: xabar Boburdan va o‘zgarmagan' : '✗ Imzo noto‘g‘ri'}`;
    }],
  ];
  const outputs = [];

  function render() {
    let h = '<div class="hh">Bobur (yuboruvchi)</div><div class="hh">Aziza (qabul qiluvchi)</div>';
    STEPS.forEach(([side, title], i) => {
      const cls = `hstep${i <= step ? ' on' : ''}${i === step ? ' cur' : ''}`;
      const body = `<div class="${cls}"><div class="t"><span class="badge">${i + 1}</span>${esc(title)}</div>${outputs[i] ? `<div class="v">${esc(outputs[i]).replace(/\n/g, '<br>')}</div>` : ''}</div>`;
      if (side === 'W') h += `<div class="wire${i <= step ? ' on' : ''}">⟶ ${esc(title)} ⟶</div>`;
      else if (side === 'L') h += body + '<div class="hstep empty"></div>';
      else h += '<div class="hstep empty"></div>' + body;
    });
    $('#hyGrid').innerHTML = h;
    $('#hyNext').textContent = step >= STEPS.length - 1 ? 'Tugadi' : step < 0 ? 'Boshlash' : 'Keyingi qadam';
    $('#hyNext').disabled = step >= STEPS.length - 1 || busy;
  }

  async function next() {
    if (busy || step >= STEPS.length - 1) return;
    if (!hasSubtle()) { toast('Brauzeringizda WebCrypto yo‘q — bu bo‘lim ishlamaydi'); return; }
    busy = true;
    step++;
    render();
    $('#hyInfo').textContent = step === 0 ? 'Ikki juft RSA-2048 kalit yaratilmoqda…' : '';
    try { outputs[step] = await STEPS[step][2](); }
    catch (e) { outputs[step] = 'Xato: ' + e.message; }
    busy = false;
    $('#hyInfo').textContent = '';
    render();
  }
  function reset() { step = -1; ctx = {}; outputs.length = 0; render(); }

  function init() {
    $('#hyMsg').value = S().msg;
    $('#hyMsg').addEventListener('input', (e) => { S().msg = e.target.value; Store.save(); if (step >= 2) reset(); });
    $('#hyNext').addEventListener('click', next);
    $('#hyReset').addEventListener('click', reset);
    render();
  }
  window.Hybrid = { init };
})();
