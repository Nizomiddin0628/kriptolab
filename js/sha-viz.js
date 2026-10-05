/* SHA-256 vizualizatori: padding, xabar jadvali, 64 raund, yakuniy qo‘shish, lavina, brute-force */
(function () {
  'use strict';
  const { $, $$, esc, debounce, Player, hasSubtle } = UI;
  const hx8 = K.hex8;
  const S = () => Store.state.sha;
  let tr = null;
  let speed = 1;
  const NAMES = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

  function compute() {
    tr = K.SHA.sha256(K.enc.encode(S().text), true);
    if (S().block >= tr.nblocks) S().block = 0;
  }

  /* ---------- 1. matn va padding ---------- */
  function renderBytes() {
    const s = S();
    const bytes = K.enc.encode(s.text);
    const chars = [];
    for (const ch of s.text) { const l = K.enc.encode(ch).length; chars.push(ch); for (let i = 1; i < l; i++) chars.push('·'); }
    $('#shaBytes').innerHTML = Array.from(bytes).map((b, i) => `<span class="byte tall" title="${K.bin8(b)}">${K.hex2(b)}<small>${esc(chars[i] === ' ' ? '␣' : chars[i])}</small></span>`).join('') || '<span class="small muted">Bo‘sh matn ham xeshlanadi — u ham bitta blok bo‘ladi.</span>';
    const L = tr.L, k = tr.k;
    $('#shaPadInfo').innerHTML = `Uzunlik <b>L = ${bytes.length} · 8 = ${L} bit</b>. Shart: <span class="formula">L + 1 + k ≡ 448 (mod 512)</span> → <b>k = ${k}</b> ta nol. ` +
      `Jami ${L} + 1 + ${k} + 64 = <b>${L + 1 + k + 64} bit = ${tr.nblocks} blok</b>.`;
    const sel = $('#shaBlockSel');
    if (tr.nblocks > 1) {
      sel.innerHTML = '<span class="small muted">Blok:</span>' + Array.from({ length: tr.nblocks }, (_, i) => `<button class="btn sm ${i === s.block ? 'sha' : 'ghost'}" data-b="${i}">${i + 1}-blok</button>`).join('');
      $$('button', sel).forEach((b) => b.addEventListener('click', () => { s.block = +b.dataset.b; s.round = 0; Store.save(); renderAllBlock(); }));
    } else sel.innerHTML = '';
    const total = tr.padded.length * 8;
    let h = '';
    const base = s.block * 512;
    for (let j = 0; j < 512; j++) {
      const g = base + j;
      const bit = (tr.padded[g >> 3] >> (7 - (g & 7))) & 1;
      let c;
      if (g < L) c = bit ? 'm' : 'm0';
      else if (g === L) c = 'one';
      else if (g < total - 64) c = '';
      else c = bit ? 'len1' : 'len';
      h += `<i class="${c}"></i>`;
    }
    $('#shaPadGrid').innerHTML = h;
  }

  /* ---------- 2. W jadvali ---------- */
  function renderW() {
    const s = S();
    const B = tr.blocks[s.block];
    const sel = s.wSel;
    const curT = s.round > 0 ? s.round - 1 : -1;
    const srcs = sel >= 16 ? [sel - 2, sel - 7, sel - 15, sel - 16] : [];
    $('#shaW').innerHTML = B.W.map((w, t) => `<button data-t="${t}" class="${t < 16 ? 'given' : ''}${t === sel ? ' sel' : ''}${srcs.includes(t) ? ' src' : ''}${t === curT ? ' cur' : ''}"><small>W${t}</small>${hx8(w)}</button>`).join('');
    $$('#shaW button').forEach((b) => b.addEventListener('click', () => { s.wSel = +b.dataset.t; Store.save(); renderW(); }));
    const d = $('#shaWDetail');
    if (sel < 16) {
      const off = s.block * 64 + sel * 4;
      const bytes = Array.from(tr.padded.slice(off, off + 4));
      d.innerHTML = `<h4>W[${sel}] — blokdan to‘g‘ridan-to‘g‘ri olinadi</h4><p class="small">Blokning ${sel * 4}…${sel * 4 + 3}-baytlari: ${bytes.map((b) => K.hex2(b)).join(' ')} → <b class="mono">${hx8(B.W[sel])}</b>. W[0…15] — blokning 16 ta 32 bitli so‘zi.</p>`;
    } else {
      const W = B.W, t = sel;
      const a = K.SHA.s1(W[t - 2]), b = K.SHA.s0(W[t - 15]);
      d.innerHTML = `<h4>W[${t}] qanday hisoblandi</h4>
        <div class="calc">W[${t}] = σ1(W[${t - 2}]) + W[${t - 7}] + σ0(W[${t - 15}]) + W[${t - 16}]  (mod 2³²)<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= ${hx8(a)} + ${hx8(W[t - 7])} + ${hx8(b)} + ${hx8(W[t - 16])}<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= <b>${hx8(W[t])}</b></div>
        <p class="small muted">σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x), σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x). Shu tufayli bitta kirish biti 64 so‘zning ko‘pchiligiga tarqaladi.</p>`;
    }
  }

  /* ---------- 3. raundlar ---------- */
  function regsAt(r) {
    const B = tr.blocks[S().block];
    return r === 0 ? B.Hin : B.rounds[r - 1].after;
  }
  function renderRegs(animate) {
    const r = S().round;
    const regs = regsAt(r);
    $('#shaRegs').innerHTML = regs.map((v, i) => {
      let bits = '';
      for (let j = 31; j >= 0; j--) bits += `<i class="${(v >>> j) & 1 ? 'b1' : ''}"></i>`;
      const isNew = r > 0 && (i === 0 || i === 4);
      const cls = animate && r > 0 ? (isNew ? ' glow' : ' slide') : '';
      return `<div class="reg${isNew ? ' new' : ''}${cls}"><span class="nm">${NAMES[i]}</span><span class="hx">${hx8(v)}</span><span class="bits">${bits}</span></div>`;
    }).join('');
    $('#shaScrub').value = r;
    $('#shaRoundLbl').textContent = r === 0 ? 'boshlang‘ich holat' : `${r}-raund / 64`;
    $('#shaStepLbl').innerHTML = r === 0 ? 'Boshlang‘ich qiymatlar H0…H7' : `${r}-raund <span class="xs muted">(t = ${r - 1})</span>`;
    renderRoundDetail(r);
  }
  function renderRoundDetail(r) {
    const d = $('#shaRoundDetail');
    if (r === 0) {
      const B = tr.blocks[S().block];
      d.innerHTML = `<h4>Boshlang‘ich qiymatlar</h4><p class="small">${S().block === 0 ? 'a…h registrlariga birinchi 8 ta tub son (2, 3, 5, …, 19) kvadrat ildizlarining kasr qismidagi dastlabki 32 bit yoziladi.' : 'Bu blok oldingi blok natijasidan (H) boshlanadi.'}</p>
        <div class="calc">${B.Hin.map((v, i) => `H${i} = ${hx8(v)}`).join('<br>')}</div><p class="small muted">▶ bosing: har raundda faqat <b>a</b> va <b>e</b> yangi hisoblanadi, qolganlari bir pastga suriladi.</p>`;
      return;
    }
    const R = tr.blocks[S().block].rounds[r - 1];
    const [a, b, c, dd, e, f, g, h] = R.before;
    d.innerHTML = `<h4>${r}-raund hisobi</h4>
      <div class="calc">Σ1(e) = Σ1(${hx8(e)}) = ${hx8(R.sig1)}<br>Ch(e,f,g) = ${hx8(R.ch)}<br>K[${R.t}] = ${hx8(R.K)}, W[${R.t}] = ${hx8(R.W)}<br>
      T1 = h + Σ1 + Ch + K + W = <b>${hx8(R.T1)}</b></div>
      <div class="calc">Σ0(a) = Σ0(${hx8(a)}) = ${hx8(R.sig0)}<br>Maj(a,b,c) = ${hx8(R.maj)}<br>T2 = Σ0 + Maj = <b>${hx8(R.T2)}</b></div>
      <div class="calc">yangi a = T1 + T2 = <b>${hx8(R.after[0])}</b><br>yangi e = d + T1 = ${hx8(dd)} + ${hx8(R.T1)} = <b>${hx8(R.after[4])}</b><br>h←g, g←f, f←e, d←c, c←b, b←a</div>
      <p class="xs muted">Ch(e,f,g): e biti 1 bo‘lsa f dan, 0 bo‘lsa g dan bit tanlaydi. Maj(a,b,c): uchtadan ko‘pchilik bit. Barcha qo‘shishlar mod 2³².</p>`;
  }
  function goRound(r, animate) {
    S().round = Math.max(0, Math.min(64, r));
    Store.save();
    renderRegs(animate);
    renderW();
  }
  const player = Player({
    next: () => { if (S().round >= 64) return false; goRound(S().round + 1, true); return S().round < 64; },
    interval: () => 1100 / speed,
    onState: (p) => { $('#shaPlay').textContent = p ? '❚❚ Pauza' : '▶ Ijro'; },
  });

  /* ---------- 4. yakun ---------- */
  function renderFinal() {
    const B = tr.blocks[S().block];
    let h = '<thead><tr><th></th><th class="mono">Boshlang‘ich H</th><th class="mono">+ 64-raunddan keyin</th><th class="mono">= yangi H</th></tr></thead><tbody>';
    for (let i = 0; i < 8; i++) h += `<tr><td class="mono">H${i} (${NAMES[i]})</td><td class="mono">${hx8(B.Hin[i])}</td><td class="mono">${hx8(B.regs[i])}</td><td class="mono"><b>${hx8(B.Hout[i])}</b></td></tr>`;
    $('#shaFinal').innerHTML = h + '</tbody>';
    $('#shaDigest').innerHTML = `<span class="xs muted">SHA-256 = H0 ‖ H1 ‖ … ‖ H7${tr.nblocks > 1 ? ` (oxirgi, ${tr.nblocks}-blokdan keyin)` : ''}</span><br><b>${tr.digest}</b>`;
  }
  async function verify() {
    const badge = $('#shaVerify');
    if (!hasSubtle()) return;
    try {
      const d = K.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', K.enc.encode(S().text))));
      badge.classList.remove('hidden');
      badge.className = 'badge ' + (d === tr.digest ? 'ok' : 'bad');
      badge.textContent = d === tr.digest ? 'Brauzer WebCrypto natijasi bilan mos' : 'Mos emas';
    } catch (e) { /* jim */ }
  }

  /* ---------- 5. lavina ---------- */
  function renderAvalanche() {
    const s = S();
    const h1 = K.SHA.sha256Hex(s.avA), h2 = K.SHA.sha256Hex(s.avB);
    const mark = (a, b) => Array.from(a).map((ch, i) => (ch !== b[i] ? `<span class="diff">${ch}</span>` : ch)).join('');
    $('#avH1').innerHTML = mark(h1, h2);
    $('#avH2').innerHTML = mark(h2, h1);
    const b1 = K.enc.encode(s.avA), b2 = K.enc.encode(s.avB);
    let inDiff = 0;
    if (b1.length === b2.length) for (let i = 0; i < b1.length; i++) inDiff += K.popcount(b1[i] ^ b2[i]);
    $('#avInDiff').innerHTML = b1.length === b2.length
      ? `Kirishda farq: <b>${inDiff} bit</b> (${b1.length * 8} bitdan).${inDiff === 1 ? ' Masalan, “c” = 0x63 = 01100011, “C” = 0x43 = 01000011 — faqat bitta bit.' : ''}`
      : 'Matnlar uzunligi har xil.';
    let grid = '', n = 0;
    for (let i = 0; i < 64; i++) {
      const x = parseInt(h1[i], 16) ^ parseInt(h2[i], 16);
      for (let j = 3; j >= 0; j--) { const d = (x >> j) & 1; n += d; grid += `<i class="${d ? 'd' : ''}"></i>`; }
    }
    $('#avGrid').innerHTML = grid;
    $('#avCount').innerHTML = `${n} <small>/ 256 bit o‘zgardi</small>`;
    $('#avPct').textContent = h1 === h2 ? 'Matnlar bir xil — xesh ham bir xil.' : `${(n / 2.56).toFixed(1)}% — ideal holatda ≈50%.`;
  }
  let avRunning = false;
  async function runExperiment() {
    if (avRunning) return;
    avRunning = true;
    const base = K.enc.encode(S().avA || 'a');
    const h0 = K.SHA.sha256(base);
    const bins = new Array(33).fill(0); // 96..160, qadam 2
    let sum = 0, count = 0;
    const hist = $('#avHist');
    hist.innerHTML = bins.map((_, i) => `<div class="${i === 16 ? 'mid' : ''}" style="height:0"></div>`).join('');
    const bars = $$('div', hist);
    for (let chunk = 0; chunk < 25; chunk++) {
      for (let k = 0; k < 20; k++) {
        const m = Uint8Array.from(base);
        const bit = (Math.random() * m.length * 8) | 0;
        m[bit >> 3] ^= 1 << (bit & 7);
        const d = K.SHA.hexBitDiff(h0, K.SHA.sha256(m));
        sum += d; count++;
        const bi = Math.round((d - 96) / 2);
        if (bi >= 0 && bi < 33) bins[bi]++;
      }
      const mx = Math.max(...bins);
      bars.forEach((b, i) => { b.style.height = (bins[i] / mx) * 100 + '%'; b.title = `${96 + i * 2} bit: ${bins[i]} marta`; });
      $('#avRunInfo').textContent = `${count} tajriba, o‘rtacha ${(sum / count).toFixed(1)} bit`;
      await new Promise((r) => requestAnimationFrame(r));
    }
    avRunning = false;
  }

  /* ---------- 6. brute-force ---------- */
  let bfRun = false;
  function renderBf() {
    const w = S().bfWord;
    $('#bfHash').textContent = /^[a-z]{4}$/.test(w) ? K.SHA.sha256Hex(w) : '4 ta kichik lotin harfi kiriting';
  }
  async function bruteForce() {
    const w = S().bfWord;
    if (!/^[a-z]{4}$/.test(w)) return;
    if (bfRun) { bfRun = false; return; }
    bfRun = true;
    $('#bfRun').textContent = 'To‘xtatish';
    $('#bfNote').style.display = 'none';
    const target = K.SHA.sha256Hex(w);
    const A = 'abcdefghijklmnopqrstuvwxyz';
    const t0 = performance.now();
    let i = 0, found = null;
    const total = 26 ** 4;
    const buf = new Uint8Array(4);
    while (bfRun && i < total) {
      const end = Math.min(total, i + 4000);
      for (; i < end; i++) {
        let x = i;
        for (let j = 3; j >= 0; j--) { buf[j] = 97 + (x % 26); x = (x / 26) | 0; }
        if (K.SHA.sha256(buf) === target) { found = String.fromCharCode(...buf); i++; break; }
      }
      const sec = (performance.now() - t0) / 1000;
      let x = i, cand = '';
      for (let j = 0; j < 4; j++) { cand = A[x % 26] + cand; x = (x / 26) | 0; }
      $('#bfInfo').innerHTML = `${i.toLocaleString('ru-RU')} ta urinish, ${Math.round(i / Math.max(sec, 0.001)).toLocaleString('ru-RU')} xesh/s, joriy: <span class="mono">${cand}</span>`;
      if (found) break;
      await new Promise((r) => requestAnimationFrame(r));
    }
    const sec = (performance.now() - t0) / 1000;
    const rate = i / Math.max(sec, 0.001);
    if (found) {
      const n8 = 62 ** 8;
      const yrs = n8 / rate / 3.156e7;
      $('#bfInfo').innerHTML = `<b style="color:var(--ok)">Topildi: “${found}”</b> — ${i.toLocaleString('ru-RU')} urinish, ${sec.toFixed(2)} s.`;
      const note = $('#bfNote');
      note.style.display = 'block';
      note.innerHTML = `Xeshni teskari hisoblamadik — shunchaki hammasini sinadik. Brauzeringiz sekundiga ~${Math.round(rate).toLocaleString('ru-RU')} xesh hisobladi: 8 belgili parol (a–z, A–Z, 0–9: 62⁸ ≈ 2,2·10¹⁴ variant) unga ~${yrs.toFixed(0)} yil kerak bo‘lardi. Ammo zamonaviy videokarta sekundiga o‘nlab milliard SHA-256 hisoblaydi — bir necha soat. Shuning uchun parollar tuz (salt) va ataylab sekin funksiya (bcrypt, Argon2) bilan saqlanadi.`;
    }
    bfRun = false;
    $('#bfRun').textContent = 'Brute-force boshlash';
  }

  /* ---------- umumiy ---------- */
  function renderAllBlock() { renderBytes(); renderW(); renderRegs(false); renderFinal(); }
  function fullRender() { compute(); renderAllBlock(); verify(); }
  function syncInputs() {
    const s = S();
    $('#shaText').value = s.text; $('#avA').value = s.avA; $('#avB').value = s.avB; $('#bfWord').value = s.bfWord;
  }
  function init() {
    syncInputs();
    const upd = debounce(() => { S().round = 0; S().block = 0; Store.save(); fullRender(); }, 200);
    $('#shaText').addEventListener('input', (e) => { S().text = e.target.value; upd(); });
    $('#shaPlay').addEventListener('click', () => { if (S().round >= 64) goRound(0, false); player.toggle(); });
    $('#shaNext').addEventListener('click', () => { player.pause(); goRound(S().round + 1, true); });
    $('#shaPrev').addEventListener('click', () => { player.pause(); goRound(S().round - 1, false); });
    $('#shaFirst').addEventListener('click', () => { player.pause(); goRound(0, false); });
    $('#shaLast').addEventListener('click', () => { player.pause(); goRound(64, false); });
    $('#shaScrub').addEventListener('input', (e) => { player.pause(); goRound(+e.target.value, false); });
    $('#shaSpeed').addEventListener('input', (e) => { speed = +e.target.value; document.documentElement.style.setProperty('--speed', speed); });
    const av = debounce(() => { Store.save(); renderAvalanche(); }, 120);
    $('#avA').addEventListener('input', (e) => { S().avA = e.target.value; av(); });
    $('#avB').addEventListener('input', (e) => { S().avB = e.target.value; av(); });
    $('#avRun').addEventListener('click', runExperiment);
    $('#bfWord').addEventListener('input', (e) => { S().bfWord = e.target.value.toLowerCase(); Store.save(); renderBf(); });
    $('#bfRun').addEventListener('click', bruteForce);
    fullRender();
    renderAvalanche();
    renderBf();
  }

  window.SHAViz = {
    init,
    load(o) { Object.assign(S(), o); syncInputs(); Store.save(); fullRender(); renderAvalanche(); },
    goRound(r) { goRound(r, true); },
    play() { player.play(); },
    onHide() { player.pause(); bfRun = false; },
  };
})();
