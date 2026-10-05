/* SHA-256 vizualizatori: matn → xesh, lavina effekti */
(function () {
  'use strict';
  const { $, $$, debounce, scramble, hasSubtle } = UI;
  const S = () => Store.state.sha;

  /* ---------- 1. matn → xesh ---------- */
  function renderHash(animate) {
    const t = S().text;
    const bytes = K.enc.encode(t);
    const h = K.SHA.sha256Hex(t);
    $('#shaInLen').textContent = `${bytes.length} bayt = ${bytes.length * 8} bit`;
    const out = $('#shaOut');
    if (animate) scramble(out, h); else out.textContent = h;
    verify(t, h);
  }
  async function verify(t, h) {
    const badge = $('#shaVerify');
    if (!hasSubtle()) return;
    try {
      const d = K.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', K.enc.encode(t))));
      badge.className = 'badge ' + (d === h ? 'ok' : 'bad');
      badge.textContent = d === h ? 'Brauzer WebCrypto natijasi bilan mos' : 'Mos emas';
    } catch (e) { /* jim */ }
  }

  /* ---------- 2. lavina ---------- */
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
      ? `Kirishda farq: <b>${inDiff} bit</b> (${b1.length * 8} bitdan).${inDiff === 1 ? ' Masalan, “c” = 01100011, “C” = 01000011 — faqat bitta bit farq.' : ''}`
      : 'Matnlar uzunligi har xil.';
    let grid = '', n = 0;
    for (let i = 0; i < 64; i++) {
      const x = parseInt(h1[i], 16) ^ parseInt(h2[i], 16);
      for (let j = 3; j >= 0; j--) { const d = (x >> j) & 1; n += d; grid += `<i class="${d ? 'd' : ''}"></i>`; }
    }
    $('#avGrid').innerHTML = grid;
    $('#avCount').innerHTML = `${n} <small>/ 256 bit o‘zgardi</small>`;
    $('#avPct').textContent = h1 === h2 ? 'Matnlar bir xil — xesh ham bir xil.' : `${(n / 2.56).toFixed(1)}% — taxminan yarmi.`;
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

  function syncInputs() {
    const s = S();
    $('#shaText').value = s.text; $('#avA').value = s.avA; $('#avB').value = s.avB;
  }
  function init() {
    syncInputs();
    const upd = debounce(() => { Store.save(); renderHash(true); }, 150);
    $('#shaText').addEventListener('input', (e) => { S().text = e.target.value; upd(); });
    const av = debounce(() => { Store.save(); renderAvalanche(); }, 120);
    $('#avA').addEventListener('input', (e) => { S().avA = e.target.value; av(); });
    $('#avB').addEventListener('input', (e) => { S().avB = e.target.value; av(); });
    $('#avRun').addEventListener('click', runExperiment);
    renderHash(false);
    renderAvalanche();
  }

  window.SHAViz = {
    init,
    load(o) { Object.assign(S(), o); syncInputs(); Store.save(); renderHash(true); renderAvalanche(); },
  };
})();
