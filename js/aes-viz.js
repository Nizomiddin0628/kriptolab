/* AES vizualizatori: PKCS7, CBC zanjiri, raundlar animatsiyasi, kalit kengaytirish, ECB rasm */
(function () {
  'use strict';
  const { $, $$, esc, debounce, toast, Player, hasSubtle } = UI;
  const h2 = K.hex2;
  const OP_NAMES = {
    input: 'Ochiq matn bloki', xorIV: 'CBC zanjiri: XOR', subBytes: 'SubBytes', shiftRows: 'ShiftRows',
    mixColumns: 'MixColumns', addRoundKey: 'AddRoundKey', output: 'Shifr blok',
  };
  let res = null;      // cbcEncrypt natijasi
  let steps = [];      // tanlangan blok qadamlari
  let speed = 1;
  let lastRendered = -1;
  const S = () => Store.state.aes;

  /* ---------- ma’lumotni hisoblash ---------- */
  function ensureKey() {
    const s = S();
    if (!s.key || s.key.length !== s.keySize * 2) { s.key = K.toHex(K.randBytes(s.keySize)); }
    if (!s.iv || s.iv.length !== 32) s.iv = K.toHex(K.randBytes(16));
  }

  function compute() {
    const s = S();
    const keyHex = s.key.replace(/\s/g, '').toLowerCase();
    const ivHex = s.iv.replace(/\s/g, '').toLowerCase();
    const info = $('#aesKeyInfo');
    if (!/^[0-9a-f]*$/.test(keyHex) || keyHex.length !== s.keySize * 2) {
      info.innerHTML = `<span style="color:var(--bad)">Kalit ${s.keySize * 2} ta hex belgidan iborat bo‘lishi kerak (hozir ${keyHex.length}).</span>`;
      res = null; return false;
    }
    if (!/^[0-9a-f]{32}$/.test(ivHex)) {
      info.innerHTML = `<span style="color:var(--bad)">IV 32 ta hex belgidan iborat bo‘lishi kerak (hozir ${ivHex.length}).</span>`;
      res = null; return false;
    }
    info.textContent = `${s.keySize * 8} bitli kalit → ${s.keySize / 4 + 6} raund`;
    res = K.AES.cbcEncrypt(K.enc.encode(s.text), K.fromHex(keyHex), K.fromHex(ivHex), true);
    if (s.block >= res.blocks.length) s.block = 0;
    buildSteps();
    return true;
  }

  function buildSteps() {
    const b = res.blocks[S().block];
    const n = S().block + 1;
    steps = [];
    steps.push({ op: 'input', round: null, before: b.p, after: b.p, label: `P${n}: ochiq matn bloki` });
    steps.push({ op: 'xorIV', round: null, before: b.p, after: b.x, roundKey: b.chainIn, label: n === 1 ? `P1 ⊕ IV` : `P${n} ⊕ C${n - 1}` });
    for (const st of b.steps) {
      const label = st.round === 0 ? 'Boshlang‘ich AddRoundKey (K0)' : `${st.round}-raund: ${OP_NAMES[st.op]}`;
      steps.push(Object.assign({}, st, { label }));
    }
    steps.push({ op: 'output', round: null, before: b.c, after: b.c, label: `C${n}: shifr blok tayyor` });
    if (S().step >= steps.length) S().step = 0;
  }

  /* ---------- 1. Padding ---------- */
  function renderPadding() {
    const s = S();
    const bytes = K.enc.encode(s.text);
    const pad = res.pad;
    $('#aesPadInfo').innerHTML =
      `Matn <b>${bytes.length} bayt</b>. 16 ga karrali bo‘lishi uchun <b>${pad} bayt</b> yetishmaydi → oxiriga ${pad} marta <b>0x${h2(pad)}</b> qo‘shildi. ` +
      `Jami <b>${res.padded.length} bayt = ${res.blocks.length} blok</b>.` + (bytes.length % 16 === 0 ? ' (Matn 16 ga karrali bo‘lgani uchun butun bitta blok qo‘shildi.)' : '');
    const box = $('#aesPadBytes');
    let html = '';
    const chars = Array.from(s.text);
    // har bir baytga belgi (UTF-8 ko‘p baytli belgilar uchun birinchi baytga)
    const map = [];
    chars.forEach((ch) => { const l = K.enc.encode(ch).length; map.push(ch); for (let i = 1; i < l; i++) map.push('·'); });
    res.padded.forEach((b, i) => {
      const isPad = i >= bytes.length;
      const lab = isPad ? 'pad' : (map[i] === ' ' ? '␣' : esc(map[i] || ''));
      html += `<span class="byte tall${isPad ? ' pad' : ''}" title="${i}-bayt">${h2(b)}<small>${lab}</small></span>`;
      if (i % 16 === 15 && i !== res.padded.length - 1) html += '<span style="flex-basis:100%;height:4px"></span>';
    });
    box.innerHTML = html;
  }

  /* ---------- 2. CBC zanjiri ---------- */
  function renderChain() {
    const sel = S().block;
    const hx = (arr, padFrom) => Array.from(arr, (b, i) => (padFrom != null && i >= padFrom ? `<span class="pad" style="background:var(--hot-soft);border-radius:2px">${h2(b)}</span>` : h2(b))).join('');
    const textLen = K.enc.encode(S().text).length;
    let html = `<div class="chain-block chain-iv" aria-label="IV"><span class="lbl">IV (tasodifiy)</span><span class="hx">${hx(K.fromHex(S().iv))}</span><span class="arr">↓ birinchi blokka</span></div>`;
    res.blocks.forEach((b, i) => {
      const padFrom = Math.max(0, textLen - i * 16);
      html += `<div class="chain-block${i === sel ? ' sel' : ''}" data-block="${i}" tabindex="0" role="button" aria-label="${i + 1}-blokni ko‘rish">
        <span class="lbl">P${i + 1}</span><span class="hx">${hx(b.p, padFrom < 16 ? padFrom : null)}</span>
        <span class="arr">↓</span><span class="op">⊕</span><span class="xs muted">${i === 0 ? 'IV' : 'C' + i}</span>
        <span class="arr">↓</span><span class="box">AES<sub>K</sub></span><span class="arr">↓</span>
        <span class="lbl">C${i + 1}</span><span class="hx" style="color:var(--aes);font-weight:700">${hx(b.c)}</span></div>`;
    });
    const box = $('#aesChain');
    box.innerHTML = html;
    $$('.chain-block[data-block]', box).forEach((el) => {
      const go = () => { S().block = +el.dataset.block; S().step = 0; Store.save(); buildSteps(); renderChain(); renderStep(false); $('#aesVizPanel').scrollIntoView({ behavior: 'smooth', block: 'start' }); };
      el.addEventListener('click', go);
      el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
    });
    $('#aesCt').textContent = K.toHex(res.ct);
    try {
      const pt = K.AES.cbcDecrypt(res.ct, K.fromHex(S().key), K.fromHex(S().iv));
      $('#aesDec').textContent = K.dec.decode(pt) + '   (' + UI.pyBytes(K.dec.decode(pt)) + ')';
    } catch (e) { $('#aesDec').textContent = 'Xato: ' + e.message; }
  }

  async function verifyWebCrypto() {
    const badge = $('#aesVerify');
    badge.classList.add('hidden');
    if (!hasSubtle() || !res) return;
    const s = S();
    try {
      const key = await crypto.subtle.importKey('raw', K.fromHex(s.key), 'AES-CBC', false, ['encrypt']);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: K.fromHex(s.iv) }, key, K.enc.encode(s.text)));
      const same = K.toHex(ct) === K.toHex(res.ct);
      badge.className = 'badge ' + (same ? 'ok' : 'bad');
      badge.textContent = same ? 'Brauzer WebCrypto natijasi bilan mos' : 'WebCrypto bilan mos emas';
    } catch (e) {
      badge.className = 'badge';
      badge.textContent = s.keySize === 24 ? 'AES-192 ni brauzer WebCrypto qo‘llamaydi' : 'WebCrypto mavjud emas';
    }
  }

  /* ---------- 3. Raund animatsiyasi ---------- */
  function gridHTML(bytes, cls) {
    let h = '';
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
      const i = r + 4 * c;
      h += `<div class="cell ${cls ? cls(i) : ''}" data-i="${i}" style="grid-row:${r + 1};grid-column:${c + 1}">${h2(bytes[i])}</div>`;
    }
    return h;
  }

  function sourceOf(op, i) {
    const r = i % 4, c = (i / 4) | 0;
    if (op === 'shiftRows') return [r + 4 * ((c + r) % 4)];
    if (op === 'mixColumns') return [0, 1, 2, 3].map((k) => k + 4 * c);
    if (op === 'input' || op === 'output') return [];
    return [i];
  }

  function renderStep(animate) {
    if (!res) return;
    const s = S();
    const st = steps[s.step];
    const focus = s.focus;
    const srcs = new Set(sourceOf(st.op, focus));
    const before = $('#aesBefore'), after = $('#aesAfter');
    const showBefore = st.op !== 'input';
    before.innerHTML = gridHTML(st.before, (i) => (showBefore && srcs.has(i) ? 'src' : ''));
    before.parentElement.style.opacity = showBefore ? '1' : '.35';
    after.innerHTML = gridHTML(st.after, (i) => {
      let c = '';
      if (st.op !== 'input' && st.op !== 'output' && st.before[i] !== st.after[i]) c += ' changed';
      if (i === focus) c += ' focus';
      return c;
    });
    $$('.cell', after).forEach((el) => el.addEventListener('click', () => { S().focus = +el.dataset.i; Store.save(); renderStep(false); }));
    $$('.cell', before).forEach((el) => el.addEventListener('click', () => { S().focus = +el.dataset.i; Store.save(); renderStep(false); }));

    if (animate && !UI.reduced()) animateGrid(after, st.op);

    $('#aesStepLbl').innerHTML = `${esc(st.label)} <span class="xs muted">(${s.step + 1} / ${steps.length})</span>`;
    $('#aesBlockLbl').textContent = `${s.block + 1}-blok / ${res.blocks.length}`;
    $$('#aesScrub button').forEach((b, i) => { b.classList.toggle('cur', i === s.step); b.classList.toggle('on', i <= s.step); });
    renderDetail(st, focus);
    lastRendered = s.step;
  }

  function animateGrid(grid, op) {
    const cells = $$('.cell', grid);
    const sp = speed;
    if (op === 'shiftRows') {
      const a = cells[0].getBoundingClientRect(), b = cells.find((c) => c.style.gridColumn.startsWith('2')).getBoundingClientRect();
      const pitch = b.left - a.left;
      cells.forEach((el) => {
        const i = +el.dataset.i, r = i % 4, c = (i / 4) | 0;
        const src = (c + r) % 4;
        if (!r) return;
        el.style.transition = 'none';
        el.style.transform = `translateX(${(src - c) * pitch}px)`;
      });
      requestAnimationFrame(() => requestAnimationFrame(() => cells.forEach((el) => { el.style.transition = ''; el.style.transform = ''; })));
    } else if (op === 'subBytes') {
      cells.forEach((el) => { const i = +el.dataset.i; el.style.animationDelay = `${(i * 28) / sp}ms`; el.classList.add('flip'); });
    } else if (op === 'mixColumns') {
      cells.forEach((el) => { const c = (+el.dataset.i / 4) | 0; el.style.animationDelay = `${(c * 170) / sp}ms`; el.classList.add('pop'); });
    } else {
      cells.forEach((el) => { const i = +el.dataset.i; el.style.animationDelay = `${(i * 18) / sp}ms`; el.classList.add('pop'); });
    }
  }

  function bitsXor(a, b) {
    return `<div class="calc">  ${K.bin8(a)}  (${h2(a)})<br>⊕ ${K.bin8(b)}  (${h2(b)})<br>= <b>${K.bin8(a ^ b)}</b>  (<b>${h2(a ^ b)}</b>)</div>`;
  }
  function miniGrid(bytes, focus, cls) {
    let h = '<div class="state" style="--cell:30px;gap:3px;margin-top:6px">';
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
      const i = r + 4 * c;
      h += `<div class="cell ${cls}${i === focus ? ' focus' : ''}" style="font-size:.72rem;border-radius:5px;grid-row:${r + 1};grid-column:${c + 1};cursor:default">${h2(bytes[i])}</div>`;
    }
    return h + '</div>';
  }

  function renderDetail(st, i) {
    const r = i % 4, c = (i / 4) | 0;
    const d = $('#aesDetail');
    const pos = `s[${r}][${c}]`;
    let html = '';
    switch (st.op) {
      case 'input': {
        const ch = String.fromCharCode(st.after[i]);
        html = `<h4>Holat jadvali</h4><p class="small">16 bayt jadvalga <b>ustun bo‘yicha</b> yoziladi: ${pos} = bayt[${r} + 4·${c}] = bayt[${i}].</p>
          <div class="calc">${pos} = 0x<b>${h2(st.after[i])}</b>${st.after[i] >= 32 && st.after[i] < 127 ? ` = '${esc(ch)}'` : ''} = ${K.bin8(st.after[i])}</div>
          <p class="small muted">▶ tugmasini bosing — har bir amal bu baytlarni qanday o‘zgartirishini ko‘rasiz. Istalgan katakni bosib, uning hisobini kuzating.</p>`;
        break;
      }
      case 'xorIV':
      case 'addRoundKey': {
        const k = st.roundKey[i];
        const name = st.op === 'xorIV' ? (S().block === 0 ? 'IV' : `C${S().block}`) : `K${st.round}`;
        html = `<h4>${st.op === 'xorIV' ? 'CBC: blokni ' + name + ' bilan XOR' : 'AddRoundKey: raund kaliti bilan XOR'}</h4>
          <p class="small">Har bir bayt ${name} ning shu joydagi bayti bilan bitma-bit XOR qilinadi (bir xil bit → 0, har xil → 1).</p>
          ${bitsXor(st.before[i], k)}
          <div class="small muted">${name} jadvali:</div>${miniGrid(st.roundKey, i, 'key')}`;
        break;
      }
      case 'subBytes': {
        const v = st.before[i], hi = v >> 4, lo = v & 15;
        let sb = '<div class="sbox"><span class="h"></span>';
        for (let x = 0; x < 16; x++) sb += `<span class="h${x === lo ? ' colh' : ''}">${x.toString(16)}</span>`;
        for (let y = 0; y < 16; y++) {
          sb += `<span class="h${y === hi ? ' rowh' : ''}">${y.toString(16)}</span>`;
          for (let x = 0; x < 16; x++) {
            const cls = y === hi && x === lo ? 'hit' : (y === hi ? 'rowh' : (x === lo ? 'colh' : ''));
            sb += `<span class="${cls}">${h2(K.AES.SBOX[y * 16 + x])}</span>`;
          }
        }
        sb += '</div>';
        html = `<h4>SubBytes: S-box jadvalidan almashtirish</h4>
          <p class="small">Bayt 0x${h2(v)}: yuqori 4 bit = <b>${hi.toString(16)}</b> (qator), quyi 4 bit = <b>${lo.toString(16)}</b> (ustun).</p>
          <div class="calc">S-box[${hi.toString(16)}][${lo.toString(16)}] = <b>${h2(st.after[i])}</b></div>${sb}`;
        break;
      }
      case 'shiftRows': {
        const src = (c + r) % 4;
        html = `<h4>ShiftRows: qatorlarni chapga surish</h4>
          <p class="small">0-qator joyida qoladi, 1-qator 1 ga, 2-qator 2 ga, 3-qator 3 ga chapga aylanma suriladi.</p>
          <div class="calc">${r}-qator chapga ${r} ga surildi:<br>yangi s[${r}][${c}] = eski s[${r}][${src}] = <b>${h2(st.after[i])}</b></div>
          <p class="small muted">Natijada har bir ustun keyingi MixColumns’da to‘rt xil ustundan bayt oladi — tarqatish (diffusion).</p>`;
        break;
      }
      case 'mixColumns': {
        const col = (arr) => [0, 1, 2, 3].map((k) => h2(arr[k + 4 * c])).join(' ');
        html = `<h4>MixColumns: ${c}-ustunni aralashtirish</h4>
          <p class="small">Har bir ustundagi 4 bayt maxsus qoida bo‘yicha o‘zaro aralashtiriladi. Natijada ustunning har bir yangi bayti eski 4 baytning hammasiga bog‘liq bo‘ladi.</p>
          <div class="calc">${c}-ustun oldin: ${col(st.before)}<br>${c}-ustun keyin: <b>${col(st.after)}</b></div>
          <p class="small muted">Bitta bayt o‘zgarsa, butun ustun o‘zgaradi — shu tufayli o‘zgarish shifr bo‘ylab tez tarqaladi.</p>`;
        break;
      }
      case 'output': {
        const n = S().block + 1;
        html = `<h4>C${n} tayyor</h4><p class="small">${res.blocks.length > n ? `Bu blok keyingi P${n + 1} bilan XOR qilinadi (CBC zanjiri).` : 'Bu oxirgi blok. Barcha bloklar ketma-ket qo‘shilib shifr matnni hosil qiladi.'}</p>
          <div class="calc" style="white-space:normal;word-break:break-all">C${n} = <b>${K.toHex(st.after)}</b></div>
          <p class="small muted">Jami ${steps.length - 3} ta amal bajarildi: ${S().keySize / 4 + 6} raund.</p>`;
        break;
      }
    }
    d.innerHTML = html;
  }

  function renderScrubber() {
    const box = $('#aesScrub');
    box.innerHTML = steps.map((st, i) => `<button class="op-${st.op}" title="${esc(st.label)}" aria-label="${esc(st.label)}"></button>`).join('');
    $$('button', box).forEach((b, i) => b.addEventListener('click', () => { player.pause(); go(i, false); }));
  }

  function go(i, animate) {
    const s = S();
    s.step = Math.max(0, Math.min(steps.length - 1, i));
    Store.save();
    renderStep(animate);
  }
  const player = Player({
    next: () => { if (S().step >= steps.length - 1) return false; go(S().step + 1, true); return S().step < steps.length - 1; },
    interval: () => 1500 / speed,
    onState: (p) => { $('#aesPlay').textContent = p ? '❚❚ Pauza' : '▶ Ijro'; },
  });

  /* ---------- umumiy ---------- */
  function fullRender() {
    if (!compute()) { $('#aesChain').innerHTML = ''; return; }
    renderPadding();
    renderChain();
    renderScrubber();
    renderStep(false);
    verifyWebCrypto();
  }

  function syncInputs() {
    const s = S();
    $('#aesText').value = s.text;
    $('#aesKey').value = s.key;
    $('#aesIv').value = s.iv;
    $$('#aesKeySize button').forEach((b) => b.setAttribute('aria-pressed', String(+b.dataset.v === s.keySize)));
  }

  function init() {
    ensureKey();
    syncInputs();
    const recompute = debounce(() => { S().step = 0; Store.save(); fullRender(); }, 200);
    $('#aesText').addEventListener('input', (e) => { S().text = e.target.value; S().block = 0; recompute(); });
    $('#aesKey').addEventListener('input', (e) => { S().key = e.target.value.trim(); recompute(); });
    $('#aesIv').addEventListener('input', (e) => { S().iv = e.target.value.trim(); recompute(); });
    $$('#aesKeySize button').forEach((b) => b.addEventListener('click', () => {
      S().keySize = +b.dataset.v; S().key = K.toHex(K.randBytes(S().keySize)); S().step = 0; Store.save(); syncInputs(); fullRender();
    }));
    $('#aesRandKey').addEventListener('click', () => {
      S().key = K.toHex(K.randBytes(S().keySize)); S().iv = K.toHex(K.randBytes(16)); S().step = 0; Store.save(); syncInputs(); fullRender();
      toast('Yangi kalit va IV yaratildi — shifr matn butunlay o‘zgardi');
    });
    $('#aesPlay').addEventListener('click', () => { if (S().step >= steps.length - 1) go(0, false); player.toggle(); });
    $('#aesNext').addEventListener('click', () => { player.pause(); go(S().step + 1, true); });
    $('#aesPrev').addEventListener('click', () => { player.pause(); go(S().step - 1, false); });
    $('#aesFirst').addEventListener('click', () => { player.pause(); go(0, false); });
    $('#aesLast').addEventListener('click', () => { player.pause(); go(steps.length - 1, false); });
    $('#aesSpeed').addEventListener('input', (e) => { speed = +e.target.value; document.documentElement.style.setProperty('--speed', speed); });
    fullRender();
  }

  /* Tashqaridan chaqirish (amaliy topshiriqdan) */
  function load(opts) {
    const s = S();
    Object.assign(s, { text: opts.text, keySize: opts.keySize || s.keySize, block: opts.block || 0, step: opts.step || 0, focus: opts.focus || 0 });
    if (opts.key) s.key = opts.key;
    if (opts.iv) s.iv = opts.iv;
    ensureKey();
    Store.save();
    syncInputs();
    fullRender();
  }

  window.AESViz = {
    init, load,
    onHide() { player.pause(); },
    stepIndex(op, round) { return steps.findIndex((s) => s.op === op && (round == null || s.round === round)); },
    go(i) { go(i, true); },
  };
})();
