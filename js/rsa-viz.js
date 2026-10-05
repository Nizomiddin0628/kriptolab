/* RSA vizualizatori: kalit oqimi, mini-RSA qadamlari, mini-imzo, haqiqiy RSA-2048 (WebCrypto) */
(function () {
  'use strict';
  const { $, $$, esc, debounce, toast, Player, sleep, hasSubtle, pyBytes } = UI;
  const S = () => Store.state.rsa;
  let speed = 1;
  let calc = null;
  let selLetter = 0;

  /* =================== kalit oqimi =================== */
  let flowMode = 'enc';
  let flowBusy = false;
  function flowKeys() {
    const L = $('#flowLeftKeys'), R = $('#flowRightKeys');
    if (flowMode === 'enc') {
      L.innerHTML = '<span class="keychip pub">Azizaning ochiq kaliti</span>';
      R.innerHTML = '<span class="keychip pub">ochiq kalit (e, n)</span><span class="keychip priv">yopiq kalit (d, n)</span>';
      $('#flowCaption').textContent = 'Bobur Azizaga maxfiy xabar yubormoqchi.';
    } else {
      L.innerHTML = '<span class="keychip pub">ochiq kalit (e, n)</span><span class="keychip priv">yopiq kalit (d, n)</span>';
      R.innerHTML = '<span class="keychip pub">Boburning ochiq kaliti</span>';
      $('#flowCaption').textContent = 'Bobur xabarni o‘zi yuborganini isbotlamoqchi.';
    }
    const p = $('#flowPacket');
    p.className = 'packet'; p.textContent = 'salom'; place(p, 0, true);
  }
  function place(p, pct, instant) {
    if (instant) p.style.transition = 'none';
    p.style.left = pct + '%';
    p.style.transform = `translateX(-${pct}%)`;
    if (instant) { void p.offsetWidth; p.style.transition = ''; }
  }
  async function flowPlay() {
    if (flowBusy) return;
    flowBusy = true;
    const p = $('#flowPacket'), cap = $('#flowCaption');
    const wait = (ms) => sleep(ms / speed);
    const salom = Array.from(K.enc.encode('salom'));
    const cnums = salom.map((m) => K.RSA.modPow(m, 17, 3233).toString());
    if (flowMode === 'enc') {
      p.className = 'packet'; p.textContent = '(e = 17, n = 3233)'; place(p, 100, true);
      cap.textContent = '1. Aziza ochiq kalitini hammaga e’lon qiladi — uni yashirish shart emas.';
      await wait(500); place(p, 0); await wait(1700);
      p.textContent = 'salom';
      cap.textContent = '2. Bobur “salom” ni Azizaning ochiq kaliti bilan shifrlaydi: C = M¹⁷ mod 3233.';
      await wait(1400);
      p.classList.add('locked'); p.textContent = cnums.join(' ');
      await wait(1200);
      cap.textContent = '3. Kanal orqali faqat shifr matn o‘tadi. Tinglovchida yopiq kalit yo‘q — o‘qiy olmaydi.';
      place(p, 100); await wait(1900);
      cap.textContent = '4. Aziza yopiq kaliti bilan ochadi: M = C²⁷⁵³ mod 3233.';
      await wait(1300);
      p.classList.remove('locked'); p.textContent = 'salom';
      cap.textContent = 'Ochiq kalit bilan qulflandi, faqat yopiq kalit bilan ochildi.';
    } else {
      const h = BigInt('0x' + K.SHA.sha256Hex('salom')) % 3233n;
      const s = K.RSA.modPow(h, 2753, 3233);
      p.className = 'packet'; p.textContent = 'salom'; place(p, 0, true);
      cap.textContent = `1. Bobur xabar xeshini oladi: h = SHA-256("salom") mod n = ${h}.`;
      await wait(1600);
      p.classList.add('signed'); p.textContent = `salom + imzo s = ${s}`;
      cap.textContent = `2. Xeshni YOPIQ kaliti bilan imzolaydi: s = h²⁷⁵³ mod 3233 = ${s}.`;
      await wait(1600);
      cap.textContent = '3. Xabar va imzo ochiq holda yuboriladi — imzo maxfiylik emas, haqiqiylik beradi.';
      place(p, 100); await wait(1900);
      cap.textContent = `4. Aziza OCHIQ kalit bilan tekshiradi: s¹⁷ mod 3233 = ${K.RSA.modPow(s, 17, 3233)} = h ✓. Xabar Boburdan va o‘zgarmagan.`;
    }
    flowBusy = false;
  }

  /* =================== mini-RSA =================== */
  const STEP_TITLES = ['Ikkita tub son', 'Modul n', 'Eyler funksiyasi φ(n)', 'Ochiq ko‘rsatkich e', 'Yopiq ko‘rsatkich d', 'Shifrlash', 'Ochish (deshifrlash)', 'Nega bu xavfsiz'];

  function validE(phi, max) {
    const out = [];
    for (let e = 3; e < phi && out.length < (max || 6); e += 2) if (K.RSA.gcd(e, phi) === 1n) out.push(e);
    return out;
  }

  function computeMini() {
    const s = S();
    const p = +s.p, q = +s.q, e = +s.e;
    const err = [];
    if (!K.RSA.isPrimeSmall(p)) err.push(`p = ${p} tub son emas.`);
    if (!K.RSA.isPrimeSmall(q)) err.push(`q = ${q} tub son emas.`);
    if (p === q) err.push('p va q har xil bo‘lishi kerak.');
    if (err.length) return { err };
    const n = p * q;
    if (n <= 255) return { err: [`n = ${n}. Har bir bayt (0–255) n dan kichik bo‘lishi uchun n > 255 kerak — kattaroq tub sonlar tanlang.`] };
    if (n > 5e7) return { err: ['Mini-rejim uchun p va q ni 7000 dan kichik tanlang.'] };
    const phi = (p - 1) * (q - 1);
    if (e <= 1 || e >= phi) return { err: [`e 1 < e < φ(n) = ${phi} oralig‘ida bo‘lishi kerak.`] };
    const eg = K.RSA.egcdTrace(e, phi);
    if (eg.gcd !== 1n) return { err: [`gcd(${e}, ${phi}) = ${eg.gcd} ≠ 1. Mos e qiymatlari: ${validE(phi).join(', ')}.`] };
    const d = eg.d;
    const bytes = Array.from(K.enc.encode(s.msg));
    const letters = bytes.map((m) => {
      const encT = K.RSA.modPowTrace(m, e, n);
      const decT = K.RSA.modPowTrace(encT.result, d, n);
      return { m, c: encT.result, back: decT.result, encT, decT };
    });
    return { p, q, e, n, phi, eg, d, letters, bytes };
  }

  function charsForBytes(str) {
    const out = [];
    for (const ch of str) { const l = K.enc.encode(ch).length; out.push(ch); for (let i = 1; i < l; i++) out.push('·'); }
    return out;
  }

  function powTable(t, base, exp, mod, title) {
    let h = `<div class="small" style="margin:8px 0 6px">${title}: ${exp} = <span class="mono">${t.bits}</span><sub>2</sub>. Har bitda: kvadratga oshiramiz, bit 1 bo‘lsa yana ${base} ga ko‘paytiramiz (mod ${mod}).</div>`;
    h += '<div class="table-wrap"><table><thead><tr><th>Bit</th><th>r² mod n</th><th>× asos (bit = 1)</th><th>r</th></tr></thead><tbody>';
    t.steps.forEach((st, i) => {
      h += `<tr class="appear" style="animation-delay:${(i * 90) / speed}ms"><td class="mono">${st.bit}</td><td class="mono">${st.from}² mod ${mod} = ${st.squared}</td><td class="mono">${st.bit === '1' ? `${st.squared}·${base} mod ${mod} = ${st.result}` : '—'}</td><td class="mono"><b>${st.result}</b></td></tr>`;
    });
    return h + '</tbody></table></div>';
  }

  function renderMini(animate) {
    const box = $('#rsaSteps');
    calc = computeMini();
    if (calc.err) { $('#rsaErr').textContent = calc.err.join(' '); box.innerHTML = ''; $('#rsaStepLbl').textContent = ''; return; }
    $('#rsaErr').textContent = '';
    const c = calc, s = S();
    const cur = s.step;
    const chars = charsForBytes(s.msg);
    if (selLetter >= c.letters.length) selLetter = 0;
    const L = c.letters[selLetter] || null;
    const card = (i, body) => `<div class="stepcard${i <= cur ? ' on' : ''}${i === cur ? ' cur' : ''}" data-i="${i}"><h4>${STEP_TITLES[i]}</h4>${i <= cur ? body : '<p class="small muted">Keyingi qadamda ochiladi.</p>'}</div>`;
    const egRows = c.eg.rows.map((r, i) => `<tr class="${animate && cur === 4 ? 'appear' : ''}" style="animation-delay:${(i * 160) / speed}ms"><td class="mono">${r.q == null ? '—' : r.q}</td><td class="mono">${r.r}</td><td class="mono">${r.t}</td></tr>`).join('');
    const tiles = (mode) => c.letters.map((l, i) => `<button class="letter${i === selLetter ? ' active' : ''}" data-l="${i}" style="cursor:pointer;font:inherit">
        <span class="ch">${esc(chars[i] === ' ' ? '␣' : chars[i])}</span><span class="m">M = ${l.m}</span><span class="ar">↓</span>
        <span class="c">C = ${l.c}</span>${mode === 'dec' ? `<span class="ar">↓</span><span class="back">${l.back}</span>` : ''}</button>`).join('');
    const bits = c.n.toString(2).length;
    let trial = 0; { let x = 2; while (c.n % x) { x++; trial++; } }
    let html = '';
    html += card(0, `<div class="eq">p = <span class="v">${c.p}</span> ✓ tub, q = <span class="v">${c.q}</span> ✓ tub</div><p class="small muted">Haqiqiy RSA-2048 da har biri ~1024 bitli (≈309 xonali) tasodifiy tub son.</p>`);
    html += card(1, `<div class="eq">n = p · q = ${c.p} · ${c.q} = <span class="v">${c.n}</span></div><p class="small muted">n ${bits} bitli. U ochiq kalitning bir qismi — hamma biladi.</p>`);
    html += card(2, `<div class="eq">φ(n) = (p − 1)(q − 1) = ${c.p - 1} · ${c.q - 1} = <span class="v">${c.phi}</span></div><p class="small muted">φ(n) ni faqat p va q ni biladigan odam hisoblay oladi — bu yopiq kalitning siri.</p>`);
    html += card(3, `<div class="eq">gcd(e, φ) = gcd(${c.e}, ${c.phi}) = <span class="v">1</span> ✓</div><p class="small">Ochiq kalit: <b class="mono">(e, n) = (${c.e}, ${c.n})</b>. Boshqa mos e: ${validE(c.phi, 5).join(', ')}… Amalda e = 65537.</p>`);
    html += card(4, `<p class="small">e · d ≡ 1 (mod φ) tenglamasini kengaytirilgan Evklid bilan yechamiz. Har qatorda: r<sub>yangi</sub> = r<sub>i−1</sub> − q·r<sub>i</sub>, t<sub>yangi</sub> = t<sub>i−1</sub> − q·t<sub>i</sub>.</p>
      <div class="table-wrap"><table><thead><tr><th>q (bo‘linma)</th><th>r (qoldiq)</th><th>t</th></tr></thead><tbody>${egRows}</tbody></table></div>
      <div class="eq" style="margin-top:8px">r = 1 bo‘lgan qatordagi t → d = t mod φ = <span class="v">${c.d}</span></div>
      <div class="eq">Tekshiruv: ${c.e} · ${c.d} mod ${c.phi} = <span class="v">${(BigInt(c.e) * c.d) % BigInt(c.phi)}</span> ✓</div>
      <p class="small">Yopiq kalit: <b class="mono">(d, n) = (${c.d}, ${c.n})</b></p>`);
    html += card(5, `<p class="small">Har bir bayt M alohida shifrlanadi: <span class="formula">C = M<sup>${c.e}</sup> mod ${c.n}</span>. Harfni bosing — hisobini ko‘rasiz.</p>
      <div class="letters">${tiles('enc')}</div>${L ? powTable(L.encT, L.m, c.e, c.n, `'${esc(chars[selLetter])}': ${L.m}<sup>${c.e}</sup> mod ${c.n}`) : ''}`);
    html += card(6, `<p class="small">Faqat d ni biladigan Aziza ochadi: <span class="formula">M = C<sup>${c.d}</sup> mod ${c.n}</span>.</p>
      <div class="letters">${tiles('dec')}</div>${L ? powTable(L.decT, L.c, c.d, c.n, `${L.c}<sup>${c.d}</sup> mod ${c.n}`) : ''}
      <div class="eq" style="margin-top:8px">Natija: <span class="v">${esc(K.dec.decode(Uint8Array.from(c.letters.map((l) => Number(l.back)))))}</span> ✓</div>`);
    html += card(7, `<p>Hujumchi n = ${c.n} ni biladi. p ni topish uchun ${trial + 1} ta bo‘lishni sinab ko‘rdi — kichik n bir zumda faktorlanadi.</p>
      <p class="small">Haqiqiy RSA-2048 da n 617 xonali. Klassik kompyuterlarda faktorlangan eng katta RSA soni — <b>RSA-250 (829 bit, 2020-yil)</b>, buning uchun ~2700 protsessor-yil ketgan. 2048 bit esa undan ancha uzoqda. Kvant kompyuterdagi Shor algoritmi esa buni buzishi mumkin — shuning uchun postkvant algoritmlarga o‘tilmoqda.</p>
      <p class="small muted">Sof (to‘ldirishsiz) RSA’ni bunday harfma-harf ishlatish xavfli: bir xil harf doim bir xil C beradi. Amalda OAEP qo‘llanadi.</p>`);
    box.innerHTML = html;
    $$('.letter', box).forEach((b) => b.addEventListener('click', () => { selLetter = +b.dataset.l; renderMini(false); }));
    $('#rsaStepLbl').innerHTML = `${cur + 1}. ${STEP_TITLES[cur]} <span class="xs muted">(${cur + 1} / 8)</span>`;
    if (animate) {
      const el = box.querySelector('.stepcard.cur');
      if (el) { const r = el.getBoundingClientRect(); if (r.top > window.innerHeight * 0.6 || r.top < 70) el.scrollIntoView({ behavior: UI.reduced() ? 'auto' : 'smooth', block: 'start' }); }
    }
  }

  function goMini(i, animate) {
    S().step = Math.max(0, Math.min(7, i));
    Store.save();
    renderMini(animate);
  }
  const player = Player({
    next: () => { if (S().step >= 7) return false; goMini(S().step + 1, true); return S().step < 7; },
    interval: () => 2600 / speed,
    onState: (p) => { $('#rsaPlay').textContent = p ? '❚❚ Pauza' : '▶ Ijro'; },
  });

  /* =================== mini-imzo =================== */
  function renderSig() {
    const c = calc;
    if (!c || c.err) { $('#sigSend').innerHTML = '<p class="small muted">Avval mini-RSA kalitlarini to‘g‘ri kiriting.</p>'; $('#sigCheck').innerHTML = ''; return; }
    const s = S();
    const n = BigInt(c.n);
    const hs = K.SHA.sha256Hex(s.sigMsg);
    const h = BigInt('0x' + hs) % n;
    const sig = K.RSA.modPow(h, c.d, n);
    const hr = BigInt('0x' + K.SHA.sha256Hex(s.sigRecv)) % n;
    const v = K.RSA.modPow(sig, c.e, n);
    const ok = v === hr;
    $('#sigSend').innerHTML = `<div class="calc" style="white-space:normal;word-break:break-all">SHA-256 = ${hs.slice(0, 24)}…<br>h = SHA-256 mod n = <b>${h}</b><br>s = h<sup>d</sup> mod n = ${h}<sup>${c.d}</sup> mod ${c.n} = <b>${sig}</b></div>`;
    $('#sigCheck').innerHTML = `<div class="calc" style="white-space:normal">h' = SHA-256(qabul qilingan) mod n = <b>${hr}</b><br>s<sup>e</sup> mod n = ${sig}<sup>${c.e}</sup> mod ${c.n} = <b>${v}</b></div>
      <span class="badge ${ok ? 'ok' : 'bad'}" style="font-size:.9rem">${ok ? 'Imzo to‘g‘ri: xabar o‘zgarmagan' : 'Imzo noto‘g‘ri: xabar o‘zgartirilgan!'}</span>
      ${ok && s.sigMsg !== s.sigRecv ? '<p class="xs muted" style="margin-top:6px">Kichik n da tasodifiy moslik bo‘lishi mumkin; RSA-2048 da bu amalda imkonsiz.</p>' : ''}`;
  }

  /* =================== haqiqiy RSA-2048 =================== */
  const Real = {
    keys: null,
    async generate() {
      const t0 = performance.now();
      const kp = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
      const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
      const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
      const ms = performance.now() - t0;
      await Real.importJwk(pub, priv);
      return { pub, priv, ms };
    },
    async importJwk(pub, priv) {
      const clean = (j) => { const c = Object.assign({}, j); delete c.alg; delete c.key_ops; delete c.ext; return c; };
      const oaep = { name: 'RSA-OAEP', hash: 'SHA-256' }, pss = { name: 'RSA-PSS', hash: 'SHA-256' };
      Real.keys = {
        pub, priv,
        encPub: await crypto.subtle.importKey('jwk', clean(pub), oaep, true, ['encrypt']),
        encPriv: await crypto.subtle.importKey('jwk', clean(priv), oaep, true, ['decrypt']),
        sigPub: await crypto.subtle.importKey('jwk', clean(pub), pss, true, ['verify']),
        sigPriv: await crypto.subtle.importKey('jwk', clean(priv), pss, true, ['sign']),
      };
      return Real.keys;
    },
    modulusHex(jwk) { return K.toHex(b64u(jwk.n)); },
    async encrypt(msg, keys) {
      keys = keys || Real.keys;
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, keys.encPub, K.enc.encode(msg)));
      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, keys.encPriv, ct));
      return { ct: K.toHex(ct), pt: K.dec.decode(pt) };
    },
    async sign(msg, keys) {
      keys = keys || Real.keys;
      const p = { name: 'RSA-PSS', saltLength: 222 }; // 2048 bit, SHA-256 uchun PSS.MAX_LENGTH = 256 - 32 - 2
      const sig = new Uint8Array(await crypto.subtle.sign(p, keys.sigPriv, K.enc.encode(msg)));
      const ok = await crypto.subtle.verify(p, keys.sigPub, sig, K.enc.encode(msg));
      const bad = await crypto.subtle.verify(p, keys.sigPub, sig, K.enc.encode(msg + '!'));
      return { sig: K.toHex(sig), ok, tamperedOk: bad };
    },
  };
  function b64u(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }

  const cons = () => $('#rsaConsole');
  function logLines(lines) { cons().innerHTML = lines.join('\n'); }
  let realLines = [];
  async function realGen() {
    if (!hasSubtle()) { toast('Brauzeringizda WebCrypto yo‘q'); return; }
    $('#rsaGen').disabled = true;
    $('#rsaRealStatus').textContent = 'yaratilmoqda…';
    cons().textContent = '2048 bitli kalit juftligi yaratilmoqda (ikki ~1024 bitli tub son qidirilmoqda)…';
    try {
      const r = await Real.generate();
      S().realKeys = { pub: r.pub, priv: r.priv };
      Store.save();
      showKeyInfo(r.ms);
    } catch (e) { cons().textContent = 'Xato: ' + e.message; }
    $('#rsaGen').disabled = false;
  }
  function showKeyInfo(ms) {
    const n = Real.modulusHex(Real.keys.pub);
    $('#rsaRealStatus').className = 'badge ok';
    $('#rsaRealStatus').textContent = 'kalit tayyor';
    $('#rsaEnc').disabled = false; $('#rsaSign').disabled = false;
    realLines = [
      `<span class="p">&gt;&gt;&gt; private_key, public_key = generate_rsa_keys(2048)</span>`,
      `Kalit uzunligi : <span class="k">${n.length * 4} bit</span>, e = 65537${ms ? `  (${(ms / 1000).toFixed(2)} s)` : '  (saqlangan sessiyadan)'}`,
      `n (hex)        : ${n.slice(0, 64)}… (${n.length} belgi)`,
    ];
    logLines(realLines);
  }
  async function realEnc() {
    const msg = S().realMsg;
    const r = await Real.encrypt(msg);
    realLines.push('', `Ochiq matn     : ${esc(pyBytes(msg))}`, `Shifr matn(hex): <span class="k">${r.ct.slice(0, 64)}</span> ...  (${r.ct.length / 2} bayt)`, `Deshifrlangan  : <span class="g">${esc(pyBytes(r.pt))}</span>`);
    logLines(realLines);
  }
  async function realSign() {
    const msg = S().realMsg;
    const r = await Real.sign(msg);
    realLines.push('', `Imzo (PSS, hex): ${r.sig.slice(0, 64)} ...`, `Imzo tekshiruvi: ${r.ok ? '<span class="g">TO\'G\'RI</span>' : '<span class="r">NOTO\'G\'RI</span>'}`, `Xabar oxiriga "!" qo‘shilsa: ${r.tamperedOk ? 'TO\'G\'RI' : '<span class="r">NOTO\'G\'RI</span>'}`);
    logLines(realLines);
  }

  /* =================== init =================== */
  function syncInputs() {
    const s = S();
    $('#rsaP').value = s.p; $('#rsaQ').value = s.q; $('#rsaE').value = s.e; $('#rsaMsg').value = s.msg;
    $('#sigMsg').value = s.sigMsg; $('#sigRecv').value = s.sigRecv; $('#rsaRealMsg').value = s.realMsg;
  }
  function init() {
    syncInputs();
    const upd = debounce(() => { Store.save(); renderMini(false); renderSig(); }, 200);
    [['#rsaP', 'p'], ['#rsaQ', 'q'], ['#rsaE', 'e'], ['#rsaMsg', 'msg']].forEach(([id, k]) => $(id).addEventListener('input', (e) => { S()[k] = k === 'msg' ? e.target.value : +e.target.value; upd(); }));
    $('#sigMsg').addEventListener('input', (e) => { S().sigMsg = e.target.value; upd(); });
    $('#sigRecv').addEventListener('input', (e) => { S().sigRecv = e.target.value; upd(); });
    $('#rsaRealMsg').addEventListener('input', (e) => { S().realMsg = e.target.value; Store.save(); });
    $('#rsaPlay').addEventListener('click', () => { if (S().step >= 7) goMini(0, false); player.toggle(); });
    $('#rsaNext').addEventListener('click', () => { player.pause(); goMini(S().step + 1, true); });
    $('#rsaPrev').addEventListener('click', () => { player.pause(); goMini(S().step - 1, false); });
    $('#rsaAll').addEventListener('click', () => { player.pause(); goMini(7, false); });
    $$('#flowMode button').forEach((b) => b.addEventListener('click', () => {
      if (flowBusy) return;
      flowMode = b.dataset.v; $$('#flowMode button').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); flowKeys();
    }));
    $('#flowPlay').addEventListener('click', flowPlay);
    $('#rsaGen').addEventListener('click', realGen);
    $('#rsaEnc').addEventListener('click', realEnc);
    $('#rsaSign').addEventListener('click', realSign);
    flowKeys();
    renderMini(false);
    renderSig();
    const rk = S().realKeys;
    if (rk && hasSubtle()) Real.importJwk(rk.pub, rk.priv).then(() => showKeyInfo(0)).catch(() => {});
  }

  window.RSAViz = {
    init, Real,
    loadMini(o) { Object.assign(S(), o); selLetter = 0; syncInputs(); Store.save(); renderMini(false); renderSig(); },
    go(i) { goMini(i, true); },
    play() { player.play(); },
    onHide() { player.pause(); },
    setSpeed(v) { speed = v; },
  };
})();
