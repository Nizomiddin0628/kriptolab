/* Amaliy topshiriq: 27 variant, qo‘lda hisoblash + dasturiy natija + animatsiyali tekshiruv */
(function () {
  'use strict';
  const { $, $$, esc, toast, pyBytes, hasSubtle } = UI;
  const S = () => Store.state.lab;

  const WORDS = ['encryption', 'authentication', 'security', 'cryptanalysis', 'steganography', 'information', 'cryptogram', 'algorithm', 'combinatorics', 'mathematics', 'password', 'cryptology', 'discrete logarithm', 'computer science', 'caesar cipher', 'decryption', 'cybersecurity', 'rotor machine', 'blockchain', 'encoding', 'ciphertext', 'algorithms', 'plaintext', 'cryptocurrency', 'electronic commerce', 'decoding', 'decipherment'];
  const PRIMES = [[61, 53], [47, 59], [43, 67], [37, 71], [41, 73], [29, 89], [31, 79], [53, 59], [47, 61], [43, 59], [37, 67], [41, 61], [29, 73], [31, 71], [23, 89], [47, 53], [43, 61], [37, 59], [41, 53], [29, 67], [31, 61], [23, 79], [19, 97], [43, 53], [37, 61], [41, 47], [29, 59]];

  function params(v) {
    const word = WORDS[v - 1];
    const bytes = K.enc.encode(word);
    const L = bytes.length;
    const pad = 16 - (L % 16);
    const [p, q] = PRIMES[v - 1];
    const n = p * q, phi = (p - 1) * (q - 1);
    const e = [7, 5, 11, 13, 17, 19, 23].find((x) => K.RSA.gcd(x, phi) === 1n);
    const d = Number(K.RSA.egcdTrace(e, phi).d);
    const M = bytes[0];
    const C = Number(K.RSA.modPow(M, e, n));
    const ch = word[0];
    const sb = K.AES.SBOX[M];
    const Lbits = L * 8;
    const k = (448 - ((Lbits + 1) % 512) + 512) % 512;
    const blocks = (Lbits + 1 + k + 64) / 512;
    return { v, word, bytes, L, pad, ctLen: L + pad, p, q, n, phi, e, d, M, C, ch, sb, Lbits, k, blocks };
  }

  /* ---------- savollar ---------- */
  const hx = (x) => K.hex2(x);
  function questions(P) {
    return {
      aes: [
        { id: 'a1', q: `“${P.word}” so‘zi necha baytdan iborat (UTF-8)?`, fields: [{ id: 'len', label: 'bayt', type: 'int', expect: P.L }],
          hint: 'Har bir lotin harfi va bo‘sh joy UTF-8 da 1 bayt.',
          sol: `“${P.word}” — ${P.L} ta belgi (bo‘sh joy ham hisobga olinadi), har biri 1 bayt → <b>${P.L} bayt</b>.`, anim: 'aesPad' },
        { id: 'a2', q: 'PKCS7: nechta to‘ldirish bayti qo‘shiladi va har birining qiymati qanday (hex)?', fields: [{ id: 'cnt', label: 'ta bayt', type: 'int', expect: P.pad }, { id: 'val', label: 'qiymati (hex)', type: 'hex', expect: P.pad }],
          hint: 'Yetishmagan baytlar soni = 16 − (L mod 16). Har bir to‘ldirish bayti shu sonning o‘ziga teng.',
          sol: `16 − (${P.L} mod 16) = 16 − ${P.L % 16} = <b>${P.pad}</b>. Har bir bayt qiymati ${P.pad} = <b>0x${hx(P.pad)}</b>.${P.L % 16 === 0 ? ' Matn 16 ga karrali bo‘lgani uchun butun bitta blok qo‘shiladi — aks holda ochishda oxirgi bayt padding’mi yoki matnmi, ajratib bo‘lmasdi.' : ''}`, anim: 'aesPad' },
        { id: 'a3', q: 'AES-CBC shifr matni necha bayt bo‘ladi va hex ko‘rinishda necha belgi?', fields: [{ id: 'b', label: 'bayt', type: 'int', expect: P.ctLen }, { id: 'h', label: 'hex belgi', type: 'int', expect: P.ctLen * 2 }],
          hint: 'Shifr matn = to‘ldirilgan matn uzunligi. 1 bayt = 2 ta hex belgi.',
          sol: `${P.L} + ${P.pad} = <b>${P.ctLen} bayt</b> (${P.ctLen / 16} blok), hex’da ${P.ctLen} · 2 = <b>${P.ctLen * 2} belgi</b>.`, anim: 'aesChain' },
        { id: 'a4', q: `Birinchi harf “${P.ch}” ning ASCII kodi (hex) va uning S-box’dagi qiymati (SubBytes natijasi) qanday?`, fields: [{ id: 'asc', label: 'ASCII (hex)', type: 'hex', expect: P.M }, { id: 'sb', label: 'S-box (hex)', type: 'hex', expect: P.sb }],
          hint: 'Kodning yuqori 4 biti (birinchi hex raqam) — S-box qatori, quyi 4 biti (ikkinchi hex raqam) — ustun. Jadval quyida.',
          sol: `“${P.ch}” = ${P.M} = <b>0x${hx(P.M)}</b>. Qator ${(P.M >> 4).toString(16)}, ustun ${(P.M & 15).toString(16)} → S-box[${(P.M >> 4).toString(16)}][${(P.M & 15).toString(16)}] = <b>0x${hx(P.sb)}</b>.`, anim: 'aesSub' },
      ],
      rsa: [
        { id: 'r1', q: `n = p · q = ?`, fields: [{ id: 'n', label: 'n', type: 'int', expect: P.n }], hint: 'Oddiy ko‘paytma.', sol: `n = ${P.p} · ${P.q} = <b>${P.n}</b>.`, anim: 'rsa1' },
        { id: 'r2', q: 'φ(n) = (p − 1)(q − 1) = ?', fields: [{ id: 'phi', label: 'φ(n)', type: 'int', expect: P.phi }], hint: 'Ikkala tub sondan 1 ni ayirib ko‘paytiring.', sol: `φ(n) = ${P.p - 1} · ${P.q - 1} = <b>${P.phi}</b>.`, anim: 'rsa2' },
        { id: 'r3', q: `Yopiq ko‘rsatkich d: ${P.e} · d ≡ 1 (mod ${P.phi}). d = ?`, fields: [{ id: 'd', label: 'd', type: 'int', expect: P.d }],
          hint: `Kengaytirilgan Evklid algoritmi: ${P.phi} va ${P.e} uchun qoldiqlar va t koeffitsiyentlar jadvalini tuzing. Tekshiruv: ${P.e} · d mod ${P.phi} = 1 bo‘lishi kerak.`,
          sol: `Kengaytirilgan Evklid algoritmi d = <b>${P.d}</b> ni beradi. Tekshiruv: ${P.e} · ${P.d} = ${P.e * P.d} = ${Math.floor((P.e * P.d) / P.phi)} · ${P.phi} + 1 ✓`, anim: 'rsa4' },
        { id: 'r4', q: `Birinchi harf “${P.ch}” (M = ${P.M}) ni shifrlang: C = M^${P.e} mod ${P.n} = ?`, fields: [{ id: 'c', label: 'C', type: 'int', expect: P.C }],
          hint: `Darajani bosqichma-bosqich hisoblang va har qadamda mod ${P.n} oling: M², M⁴ … yoki ${P.e} ni ikkilik ko‘rinishda yozib kvadrat-ko‘paytirish usulini qo‘llang.`,
          sol: `${P.M}^${P.e} mod ${P.n} = <b>${P.C}</b>. Tekshiruv (ochish): ${P.C}^${P.d} mod ${P.n} = ${K.RSA.modPow(P.C, P.d, P.n)} = M ✓`, anim: 'rsa5' },
      ],
      sha: [
        { id: 'h1', q: `“${P.word}” uchun xabar uzunligi L (bitda) = ?`, fields: [{ id: 'L', label: 'bit', type: 'int', expect: P.Lbits }], hint: '1 bayt = 8 bit.', sol: `L = ${P.L} · 8 = <b>${P.Lbits} bit</b>.`, anim: 'shaPad' },
        { id: 'h2', q: 'Nechta nol bit (k) qo‘shiladi? Shart: L + 1 + k ≡ 448 (mod 512)', fields: [{ id: 'k', label: 'k', type: 'int', expect: P.k }], hint: 'Avval “1” biti qo‘shiladi, keyin 448 gacha nollar, oxirida 64 bitli uzunlik.', sol: `${P.Lbits} + 1 + k = 448 → k = 448 − ${P.Lbits + 1} = <b>${P.k}</b>.`, anim: 'shaPad' },
        { id: 'h3', q: 'To‘ldirilgan xabar nechta 512 bitli blokdan iborat?', fields: [{ id: 'bl', label: 'blok', type: 'int', expect: P.blocks }], hint: 'L + 1 + k + 64 ni 512 ga bo‘ling.', sol: `${P.Lbits} + 1 + ${P.k} + 64 = ${P.Lbits + 1 + P.k + 64} bit = <b>${P.blocks} blok</b>.`, anim: 'shaPad' },
      ],
    };
  }

  function parseVal(raw, type) {
    raw = String(raw || '').trim().toLowerCase();
    if (!raw) return null;
    if (type === 'hex') { raw = raw.replace(/^0x/, ''); if (!/^[0-9a-f]{1,2}$/.test(raw)) return NaN; return parseInt(raw, 16); }
    if (!/^-?\d+$/.test(raw.replace(/\s/g, ''))) return NaN;
    return parseInt(raw.replace(/\s/g, ''), 10);
  }

  /* ---------- animatsiyaga o‘tish ---------- */
  function animate(kind, P) {
    const R = S().results;
    const keyHex = R.t1 && R.t1.key, ivHex = R.t1 && R.t1.iv;
    switch (kind) {
      case 'aesPad':
      case 'aesChain':
        App.go('aes', () => {
          AESViz.load({ text: P.word, keySize: 32, key: keyHex, iv: ivHex });
          App.focusEl(kind === 'aesPad' ? '#aesPadBytes' : '#aesChain');
        });
        break;
      case 'aesSub':
        App.go('aes', () => {
          AESViz.load({ text: P.word, keySize: 32, key: '00'.repeat(32), iv: '00'.repeat(16), focus: 0 });
          const i = AESViz.stepIndex('subBytes', 1);
          AESViz.go(i);
          App.focusEl('#aesVizPanel');
          toast('Ko‘rgazma uchun kalit va IV nolga teng: birinchi SubBytes aynan harfingizga qo‘llanadi', 5200);
        });
        break;
      case 'rsa1': case 'rsa2': case 'rsa4': case 'rsa5': {
        const step = +kind.slice(3);
        App.go('rsa', () => {
          RSAViz.loadMini({ p: P.p, q: P.q, e: P.e, msg: kind === 'rsa5' ? P.ch : P.word.replace(/\s/g, '').slice(0, 6), step: Math.max(0, step - 1) });
          App.focusEl('#rsaSteps');
          setTimeout(() => RSAViz.go(step), 700);
        });
        break;
      }
      case 'shaPad':
        App.go('sha', () => { SHAViz.load({ text: P.word, block: 0, round: 0 }); App.focusEl('#shaPadGrid'); });
        break;
      case 'shaAv': {
        const t3 = R.t3;
        App.go('sha', () => { SHAViz.load({ avA: t3.w1, avB: t3.w2 }); App.focusEl('#avGrid'); });
        break;
      }
    }
  }

  /* ---------- render ---------- */
  function renderVariants() {
    const v = S().variant;
    $('#variantPick').innerHTML = WORDS.map((w, i) => `<button aria-pressed="${v === i + 1}" data-v="${i + 1}"><b>${i + 1}</b>${esc(w)}</button>`).join('');
    $$('#variantPick button').forEach((b) => b.addEventListener('click', () => pickVariant(+b.dataset.v)));
  }
  function pickVariant(v) {
    const s = S();
    if (s.variant === v) return;
    const hasWork = Object.keys(s.checked).length || Object.keys(s.results).length;
    if (hasWork && !confirm('Variantni almashtirsangiz, joriy topshiriq natijalari o‘chiriladi. Davom etasizmi?')) return;
    Object.assign(s, { variant: v, answers: {}, checked: {}, results: {}, analysis: s.analysis, analysisChecked: false });
    Store.save();
    renderVariants();
    renderTasks();
    App.updateProgress();
  }

  function qHTML(qd, num) {
    const s = S();
    const st = s.checked[qd.id];
    const fields = qd.fields.map((f) => {
      const key = qd.id + '_' + f.id;
      const val = s.answers[key] || '';
      let cls = '';
      if (st && val) cls = parseVal(val, f.type) === f.expect ? 'ok' : 'bad';
      return `<label class="small" style="display:flex;align-items:center;gap:6px"><input type="text" inputmode="${f.type === 'hex' ? 'text' : 'numeric'}" data-a="${key}" value="${esc(val)}" class="${cls}" style="width:${f.type === 'hex' ? 90 : 120}px" aria-label="${esc(f.label)}"> ${esc(f.label)}</label>`;
    }).join('');
    return `<div class="q" data-q="${qd.id}"><div class="qt">${num}. ${qd.q}</div>
      <div class="ans">${fields}<button class="btn sm" data-check="${qd.id}">Tekshirish</button></div>
      <div class="fb" id="fb-${qd.id}"></div></div>`;
  }
  function fbHTML(qd) {
    const st = S().checked[qd.id];
    if (!st) return null;
    const anim = `<button class="btn sm ghost" data-anim="${qd.anim}" style="margin-top:8px">▶ Yechimni animatsiyada ko‘rish</button>`;
    if (st.ok) return ['ok', `<b>✓ To‘g‘ri${st.tries > 1 ? ` (${st.tries}-urinishda)` : ''}.</b> ${qd.sol}<br>${anim}`];
    if (st.revealed) return ['bad', `<b>Yechim:</b> ${qd.sol}<br>${anim}`];
    return ['bad', `<b>✗ Noto‘g‘ri.</b> Maslahat: ${qd.hint}<div class="row" style="margin-top:8px"><span class="small muted">Javobni tuzatib, qayta tekshiring yoki</span><button class="btn sm ghost" data-reveal="${qd.id}">Yechimni ko‘rsatish</button>${anim}</div>`];
  }
  function paintFb(qd) {
    const el = $('#fb-' + qd.id);
    if (!el) return;
    const r = fbHTML(qd);
    if (!r) { el.className = 'fb'; el.innerHTML = ''; return; }
    el.className = 'fb show ' + r[0];
    el.innerHTML = r[1];
  }

  function sboxTable() {
    let h = '<div class="table-wrap" style="margin-top:8px"><table style="font-size:.72rem"><thead><tr><th></th>';
    for (let x = 0; x < 16; x++) h += `<th class="mono">${x.toString(16)}</th>`;
    h += '</tr></thead><tbody>';
    for (let y = 0; y < 16; y++) {
      h += `<tr><th class="mono">${y.toString(16)}</th>`;
      for (let x = 0; x < 16; x++) h += `<td class="mono" style="padding:3px 4px">${hx(K.AES.SBOX[y * 16 + x])}</td>`;
      h += '</tr>';
    }
    return h + '</tbody></table></div>';
  }

  function pyCode(P) {
    const w = P.word;
    return {
      aes: `import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

if __name__ == "__main__":
    key = os.urandom(32)   # AES-256
    iv = os.urandom(16)
    plaintext = ${pyBytes(w)}
    ciphertext = aes_encrypt(plaintext, key, iv)
    decrypted = aes_decrypt(ciphertext, key, iv)
    print("Kalit (hex)    :", key.hex())
    print("IV (hex)       :", iv.hex())
    print("Ochiq matn     :", plaintext)
    print("Shifr matn(hex):", ciphertext.hex())
    print("Deshifrlangan  :", decrypted)`,
      rsa: `from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

plaintext = ${pyBytes(w)}
ciphertext = public_key.encrypt(plaintext, oaep)
decrypted = private_key.decrypt(ciphertext, oaep)
print("Ochiq matn     :", plaintext)
print("Shifr matn(hex):", ciphertext.hex()[:64], "...")
print("Deshifrlangan  :", decrypted)

pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
signature = private_key.sign(plaintext, pss, hashes.SHA256())
try:
    public_key.verify(signature, plaintext, pss, hashes.SHA256())
    print("Imzo tekshiruvi: TO'G'RI")
except Exception:
    print("Imzo tekshiruvi: NOTO'G'RI")

# Qo'lda (mini-RSA) tekshiruv:
p, q, e = ${P.p}, ${P.q}, ${P.e}
n, phi = p * q, (p - 1) * (q - 1)
d = pow(e, -1, phi)
M = ord("${P.ch}")
print("n =", n, " phi =", phi, " d =", d, " C =", pow(M, e, n))`,
      sha: `import hashlib

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

text1 = "${w}"
text2 = "${(S().results.t3 && S().results.t3.w2) || defaultModified(w)}"   # bitta harf o'zgartirilgan
h1, h2 = sha256_hex(text1), sha256_hex(text2)
print("Matn 1      :", text1)
print("SHA-256(M1) :", h1)
print("Matn 2      :", text2)
print("SHA-256(M2) :", h2)
diff_bits = sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(h1, h2))
print("Farqlanuvchi bitlar soni (lavina effekti):", diff_bits, "/", len(h1) * 4)`,
    };
  }
  function defaultModified(w) { return w[0].toUpperCase() + w.slice(1); }

  function taskHeader(num, cls, title, done) {
    return `<header><span class="num">${num}</span><h3>${title}</h3><span class="st badge ${done ? 'ok' : ''}" id="st-t${num}">${done ? 'Bajarildi' : 'Bajarilmagan'}</span></header>`;
  }

  function renderTasks() {
    const s = S();
    const box = $('#labTasks');
    if (!s.variant) {
      box.innerHTML = '<div class="panel flat"><p style="margin:0">Topshiriqlar paydo bo‘lishi uchun yuqoridan variantingizni tanlang.</p></div>';
      return;
    }
    const P = params(s.variant);
    const Q = questions(P);
    const code = pyCode(P);
    const R = s.results;
    const t3w2 = (R.t3 && R.t3.w2) || defaultModified(P.word);
    box.innerHTML = `
    <div class="callout info">Variant <b>${P.v}</b>: so‘z <b>“${esc(P.word)}”</b>. RSA uchun: p = <b>${P.p}</b>, q = <b>${P.q}</b>, e = <b>${P.e}</b>.</div>

    <article class="task aes">${taskHeader(1, 'aes', 'AES-256 bilan shifrlash va deshifrlash (CBC, PKCS7)', isDone(1))}
      <div class="body">
        <h4>A. Qo‘lda hisoblang</h4>
        ${Q.aes.map((q, i) => qHTML(q, i + 1)).join('')}
        <details class="code"><summary>S-box jadvali (4-savol uchun)</summary>${sboxTable()}</details>
        <h4 style="margin-top:20px">B. Dasturiy bajaring</h4>
        <p class="small muted">Kalit (32 bayt) va IV (16 bayt) tasodifiy yaratiladi, so‘z shifrlanib, qayta ochiladi.</p>
        <div class="row"><button class="btn aes" id="t1Run">Kalit va IV yaratib, shifrlash</button>${R.t1 ? '<button class="btn ghost" id="t1Anim">▶ Shu natijani animatsiyada ko‘rish</button>' : ''}</div>
        <div class="console" id="t1Out" style="margin-top:12px">${R.t1 ? t1Console(R.t1, P) : 'Natija shu yerda chiqadi.'}</div>
        <details class="code"><summary>Python kodi (variantingiz uchun)</summary><pre>${esc(code.aes)}</pre></details>
      </div></article>

    <article class="task rsa">${taskHeader(2, 'rsa', 'RSA: kalit juftligi, shifrlash, raqamli imzo', isDone(2))}
      <div class="body">
        <h4>A. Mini-RSA ni qo‘lda hisoblang (p = ${P.p}, q = ${P.q}, e = ${P.e})</h4>
        ${Q.rsa.map((q, i) => qHTML(q, i + 1)).join('')}
        <h4 style="margin-top:20px">B. Haqiqiy RSA-2048 (OAEP + PSS)</h4>
        <div class="row"><button class="btn rsa" id="t2Run">Kalit yaratish, shifrlash, imzolash</button></div>
        <div class="console" id="t2Out" style="margin-top:12px">${R.t2 ? t2Console(R.t2, P) : 'Natija shu yerda chiqadi.'}</div>
        <details class="code"><summary>Python kodi (variantingiz uchun)</summary><pre>${esc(code.rsa)}</pre></details>
      </div></article>

    <article class="task sha">${taskHeader(3, 'sha', 'SHA-256 va lavina effekti', isDone(3))}
      <div class="body">
        <h4>A. To‘ldirishni qo‘lda hisoblang</h4>
        ${Q.sha.map((q, i) => qHTML(q, i + 1)).join('')}
        <h4 style="margin-top:20px">B. Bitta harfni o‘zgartirib, xeshlarni solishtiring</h4>
        <div class="grid-2"><label class="field">Asl so‘z<input type="text" value="${esc(P.word)}" disabled></label>
          <label class="field">O‘zgartirilgan so‘z (faqat 1 ta belgi farq qilsin)<input type="text" id="t3W2" value="${esc(t3w2)}" autocomplete="off" spellcheck="false"></label></div>
        <div class="row" style="margin-top:12px"><button class="btn sha" id="t3Run">Xeshlarni hisoblash</button><span class="small" id="t3Err" style="color:var(--bad)"></span></div>
        <div class="console" id="t3Out" style="margin-top:12px">${R.t3 ? t3Console(R.t3) : 'Natija shu yerda chiqadi.'}</div>
        <div id="t3Q">${R.t3 ? h4HTML(R.t3) : ''}</div>
        <details class="code"><summary>Python kodi (variantingiz uchun)</summary><pre>${esc(code.sha)}</pre></details>
      </div></article>

    <article class="task all">${taskHeader(4, 'all', 'Tahlil: uchala usulni solishtiring (3–4 gap)', isDone(4))}
      <div class="body">
        <p class="small muted">Simmetrik shifrlash, asimmetrik shifrlash va xesh funksiyasining qo‘llanilish sohalari (maxfiylik, kalit almashish, yaxlitlik) bo‘yicha farqini yozing.</p>
        <textarea id="t4Text" placeholder="Simmetrik shifrlash (AES)…">${esc(s.analysis || '')}</textarea>
        <ul class="checklist" id="t4Check"></ul>
        <div class="row"><button class="btn" id="t4Btn">Tekshirish</button><span class="small" id="t4Info"></span></div>
        <div id="t4Sample"></div>
      </div></article>`;

    // savollar
    const all = [...Q.aes, ...Q.rsa, ...Q.sha];
    all.forEach(paintFb);
    $$('input[data-a]', box).forEach((inp) => inp.addEventListener('input', () => { S().answers[inp.dataset.a] = inp.value; inp.classList.remove('ok', 'bad'); Store.save(); }));
    $$('input[data-a]', box).forEach((inp) => inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') { const q = inp.closest('.q'); q && q.querySelector('[data-check]').click(); } }));
    box._P = P; box._all = all;

    $('#t1Run').addEventListener('click', () => runT1(P));
    const a = $('#t1Anim'); if (a) a.addEventListener('click', () => App.go('aes', () => { AESViz.load({ text: P.word, keySize: 32, key: R.t1.key, iv: R.t1.iv }); App.focusEl('#aesChain'); }));
    $('#t2Run').addEventListener('click', () => runT2(P));
    $('#t3Run').addEventListener('click', () => runT3(P));
    $('#t3W2').addEventListener('input', (e) => { $('#t3Err').textContent = ''; });
    const ta = $('#t4Text');
    ta.addEventListener('input', () => { S().analysis = ta.value; Store.save(); paintChecklist(); });
    $('#t4Btn').addEventListener('click', checkT4);
    paintChecklist();
    if (s.analysisChecked) showSample();
    bindH4();
  }

  function onClick(e) {
    const box = $('#labTasks');
    const P = box._P;
    const t = e.target.closest('[data-check],[data-reveal],[data-anim]');
    if (!t) return;
    if (t.dataset.anim) { animate(t.dataset.anim, P); return; }
    const id = t.dataset.check || t.dataset.reveal;
    const qd = box._all.find((q) => q.id === id) || (id === 'h4' ? h4Def() : null);
    if (!qd) return;
    const s = S();
    const st = s.checked[id] || { ok: false, tries: 0, revealed: false };
    if (t.dataset.reveal) { st.revealed = true; s.checked[id] = st; }
    else {
      if (st.ok) return;
      const vals = qd.fields.map((f) => parseVal(s.answers[id + '_' + f.id], f.type));
      if (vals.some((v) => v === null)) { toast('Avval barcha maydonlarni to‘ldiring'); return; }
      if (vals.some((v) => Number.isNaN(v))) { toast('Faqat son kiriting' + (qd.fields.some((f) => f.type === 'hex') ? ' (hex: masalan 0d yoki 0x0d)' : '')); return; }
      st.tries++;
      st.ok = qd.fields.every((f, i) => vals[i] === f.expect);
      s.checked[id] = st;
      qd.fields.forEach((f, i) => { const inp = $(`input[data-a="${id}_${f.id}"]`); if (inp) { inp.classList.remove('ok', 'bad'); inp.classList.add(vals[i] === f.expect ? 'ok' : 'bad'); } });
      toast(st.ok ? 'To‘g‘ri!' : 'Noto‘g‘ri — maslahatni o‘qing');
    }
    Store.save();
    paintFb(qd);
    refreshStatus();
  }

  /* ---------- dasturiy qismlar ---------- */
  function t1Console(r, P) {
    return `<span class="p">$ python aes_lab.py</span>\nKalit (hex)    : <span class="k">${r.key}</span>\nIV (hex)       : <span class="k">${r.iv}</span>\nOchiq matn     : ${esc(pyBytes(P.word))}\nShifr matn(hex): <span class="k">${r.ct}</span>\nDeshifrlangan  : <span class="g">${esc(pyBytes(r.dec))}</span>${r.web === true ? '\n\n<span class="g"># Brauzer WebCrypto AES-CBC natijasi bilan mos ✓</span>' : ''}`;
  }
  async function runT1(P) {
    const key = K.randBytes(32), iv = K.randBytes(16);
    const res = K.AES.cbcEncrypt(P.bytes, key, iv);
    const dec = K.dec.decode(K.AES.cbcDecrypt(res.ct, key, iv));
    const r = { key: K.toHex(key), iv: K.toHex(iv), ct: K.toHex(res.ct), dec, web: null };
    if (hasSubtle()) {
      try {
        const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
        r.web = K.toHex(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, k, P.bytes))) === r.ct;
      } catch (e) { /* jim */ }
    }
    S().results.t1 = r;
    Store.save();
    renderTasks();
    toast('AES natijasi tayyor');
  }

  function t2Console(r, P) {
    return `<span class="p">$ python rsa_lab.py</span>\nKalit uzunligi : 2048 bit, e = 65537\nOchiq matn     : ${esc(pyBytes(P.word))}\nShifr matn(hex): <span class="k">${r.ct.slice(0, 64)}</span> ...\nDeshifrlangan  : <span class="g">${esc(pyBytes(r.dec))}</span>\nImzo tekshiruvi: ${r.ok ? '<span class="g">TO\'G\'RI</span>' : '<span class="r">NOTO\'G\'RI</span>'}\n\n<span class="p"># Mini-RSA (qo‘lda):</span>\nn = ${P.n}  phi = ${P.phi}  d = ${P.d}  C = ${P.C}`;
  }
  async function runT2(P) {
    if (!hasSubtle()) { toast('Brauzeringizda WebCrypto yo‘q'); return; }
    const btn = $('#t2Run'); btn.disabled = true;
    $('#t2Out').textContent = 'RSA-2048 kalit juftligi yaratilmoqda…';
    try {
      const prev = RSAViz.Real.keys;
      const g = await RSAViz.Real.generate();
      const keys = RSAViz.Real.keys;
      RSAViz.Real.keys = prev;
      const e = await RSAViz.Real.encrypt(P.word, keys);
      const sg = await RSAViz.Real.sign(P.word, keys);
      S().results.t2 = { n: RSAViz.Real.modulusHex(g.pub), ct: e.ct, dec: e.pt, sig: sg.sig, ok: sg.ok };
      Store.save();
      renderTasks();
      toast('RSA natijasi tayyor');
    } catch (err) { $('#t2Out').textContent = 'Xato: ' + err.message; btn.disabled = false; }
  }

  function t3Console(r) {
    return `<span class="p">$ python sha_lab.py</span>\nMatn 1      : ${esc(r.w1)}\nSHA-256(M1) : <span class="k">${r.h1}</span>\nMatn 2      : ${esc(r.w2)}\nSHA-256(M2) : <span class="k">${r.h2}</span>\nFarqlanuvchi bitlar soni (lavina effekti): <span class="g">${r.diff} / 256</span>`;
  }
  function runT3(P) {
    const w2 = $('#t3W2').value;
    const a = Array.from(P.word), b = Array.from(w2);
    let diff = 0;
    if (a.length === b.length) a.forEach((c, i) => { if (c !== b[i]) diff++; });
    if (a.length !== b.length || diff !== 1) {
      $('#t3Err').textContent = a.length !== b.length ? 'Uzunlik bir xil bo‘lishi kerak — faqat bitta belgini almashtiring.' : (diff === 0 ? 'So‘z o‘zgarmagan — bitta harfni almashtiring.' : `${diff} ta belgi farq qiladi — faqat bittasini o‘zgartiring.`);
      return;
    }
    const h1 = K.SHA.sha256Hex(P.word), h2 = K.SHA.sha256Hex(w2);
    const s = S();
    s.results.t3 = { w1: P.word, w2, h1, h2, diff: K.SHA.hexBitDiff(h1, h2) };
    delete s.checked.h4; delete s.answers.h4_x;
    Store.save();
    renderTasks();
    toast('Xeshlar hisoblandi');
  }
  function h4Def() {
    const r = S().results.t3;
    const x = parseInt(r.h1[0], 16) ^ parseInt(r.h2[0], 16);
    const b4 = (v) => v.toString(2).padStart(4, '0');
    return { id: 'h4', fields: [{ id: 'x', label: 'bit', type: 'int', expect: K.popcount(x) }],
      hint: 'Har bir hex belgini 4 bitga yozing (masalan 6 = 0110), bitma-bit XOR qiling va 1 lar sonini sanang.',
      sol: `${r.h1[0]} = ${b4(parseInt(r.h1[0], 16))}, ${r.h2[0]} = ${b4(parseInt(r.h2[0], 16))} → XOR = ${b4(x)} → <b>${K.popcount(x)} bit</b>. Butun xesh bo‘yicha shunday hisoblansa: ${r.diff} / 256 bit (${(r.diff / 2.56).toFixed(1)}%) — lavina effekti.`, anim: 'shaAv' };
  }
  function h4HTML(r) {
    return qHTML(Object.assign(h4Def(), { q: `Ikkala xeshning birinchi hex belgilari: “${r.h1[0]}” va “${r.h2[0]}”. Ularni XOR qilsak, nechta bit farq qiladi?` }), 4);
  }
  function bindH4() {
    const el = $('#t3Q');
    if (!el || !S().results.t3) return;
    paintFb(h4Def());
  }

  /* ---------- 4-topshiriq ---------- */
  const KEYWORDS = [
    ['maxfiylik', /maxfiy/i], ['kalit almashish', /kalit\S*\s+(almash|yetkaz|uzat|kelish|o.ra)/i], ['yaxlitlik', /yaxlit/i],
    ['raqamli imzo', /imzo/i], ['tezlik', /\btez|sekin/i], ['bir tomonlamalik', /qaytar|bir tomonlama/i],
  ];
  function sentences(t) { return (t || '').split(/[.!?]+/).map((x) => x.trim()).filter((x) => x.split(/\s+/).length >= 4).length; }
  function paintChecklist() {
    const t = S().analysis || '';
    const ul = $('#t4Check');
    if (!ul) return;
    ul.innerHTML = KEYWORDS.map(([l, re]) => `<li class="${re.test(t) ? 'hit' : ''}">${l}</li>`).join('') + `<li class="${sentences(t) >= 3 ? 'hit' : ''}">${sentences(t)} ta gap (kamida 3)</li>`;
  }
  function t4Ok() {
    const t = S().analysis || '';
    return sentences(t) >= 3 && KEYWORDS.filter(([, re]) => re.test(t)).length >= 3;
  }
  function checkT4() {
    const s = S();
    s.analysisChecked = true;
    Store.save();
    const n = KEYWORDS.filter(([, re]) => re.test(s.analysis || '')).length;
    $('#t4Info').innerHTML = t4Ok() ? '<span style="color:var(--ok);font-weight:700">Qabul qilindi.</span> Namunaviy javob bilan solishtiring.'
      : `<span style="color:var(--bad)">Kamida 3 ta gap va 3 ta asosiy tushuncha kerak (hozir ${sentences(s.analysis)} gap, ${n} tushuncha).</span>`;
    showSample();
    refreshStatus();
  }
  function showSample() {
    $('#t4Sample').innerHTML = `<div class="callout ok"><b>Namunaviy javob.</b> Simmetrik shifrlash (AES) bitta maxfiy kalit bilan juda tez ishlaydi, shuning uchun katta hajmdagi ma’lumotning maxfiyligini ta’minlashda qo‘llanadi, lekin kalitni tomonlarga xavfsiz yetkazish muammosi bor. Asimmetrik shifrlash (RSA) ochiq va yopiq kalit juftligiga asoslangan va sekin ishlaydi, shu sababli asosan kalit almashish va raqamli imzo uchun ishlatiladi. Xesh funksiya (SHA-256) kalitsiz va bir tomonlama: u ma’lumotni shifrlamaydi, balki doim 256 bitli “barmoq izi” orqali uning yaxlitligini tekshiradi. Amalda uchalasi gibrid tizimda (masalan, TLS) birga ishlaydi: asimmetrik usul kalitni yetkazadi, AES ma’lumotni shifrlaydi, SHA-256 yaxlitlik va imzoni ta’minlaydi.</div>`;
  }

  /* ---------- holat ---------- */
  function qResolved(id) { const st = S().checked[id]; return !!(st && (st.ok || st.revealed)); }
  function isDone(n) {
    const s = S();
    if (!s.variant) return false;
    if (n === 1) return !!s.results.t1 && ['a1', 'a2', 'a3', 'a4'].every(qResolved);
    if (n === 2) return !!s.results.t2 && ['r1', 'r2', 'r3', 'r4'].every(qResolved);
    if (n === 3) return !!s.results.t3 && ['h1', 'h2', 'h3', 'h4'].every(qResolved);
    if (n === 4) return s.analysisChecked && t4Ok();
    return false;
  }
  function refreshStatus() {
    [1, 2, 3, 4].forEach((n) => { const el = $('#st-t' + n); if (el) { const d = isDone(n); el.className = 'st badge ' + (d ? 'ok' : ''); el.textContent = d ? 'Bajarildi' : 'Bajarilmagan'; } });
    App.updateProgress();
  }

  /* ---------- hisobot ---------- */
  function reportText() {
    const s = S();
    const line = '='.repeat(64);
    const out = [];
    out.push('2-AMALIY ISH');
    out.push('Zamonaviy simmetrik, ochiq kalitli shifrlash va xesh funksiya');
    out.push('algoritmlarini dasturiy amalga oshirish');
    out.push(line);
    out.push(`Talaba : ${s.name || '—'}`);
    out.push(`Guruh  : ${s.group || '—'}`);
    if (!s.variant) { out.push('', 'Variant tanlanmagan. “Amaliy topshiriq” bo‘limida variantni tanlang.'); return out.join('\n'); }
    const P = params(s.variant);
    out.push(`Variant: ${P.v} — "${P.word}"`);
    out.push(`Sana   : ${new Date().toLocaleString('uz-UZ')}`);
    const Q = questions(P);
    const strip = (h) => h.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ');
    const qBlock = (list, start) => list.forEach((qd, i) => {
      const st = s.checked[qd.id];
      const ans = qd.fields.map((f) => `${s.answers[qd.id + '_' + f.id] || '—'} ${f.label}`).join(', ');
      const mark = !st ? '[tekshirilmagan]' : st.ok ? `[to‘g‘ri, ${st.tries}-urinish]` : st.revealed ? '[yechim ko‘rilgan]' : '[noto‘g‘ri]';
      out.push(`  ${(start || 1) + i}) ${strip(qd.q)}`);
      out.push(`     Javob: ${ans}  ${mark}`);
      if (st && (st.ok || st.revealed)) out.push(`     Yechim: ${strip(qd.sol)}`);
    });
    const R = s.results;
    out.push('', line, '1-TOPSHIRIQ. AES-256 (CBC rejimi, PKCS7 to‘ldirish)', line, 'Qo‘lda hisoblash:');
    qBlock(Q.aes);
    out.push('', 'Dastur natijasi:');
    if (R.t1) out.push(`Kalit (hex)    : ${R.t1.key}`, `IV (hex)       : ${R.t1.iv}`, `Ochiq matn     : ${pyBytes(P.word)}`, `Shifr matn(hex): ${R.t1.ct}`, `Deshifrlangan  : ${pyBytes(R.t1.dec)}`);
    else out.push('  (bajarilmagan)');
    out.push('', line, '2-TOPSHIRIQ. RSA (2048 bit, OAEP, PSS imzo)', line, `Mini-RSA: p = ${P.p}, q = ${P.q}, e = ${P.e}, M = ${P.M} ('${P.ch}')`);
    qBlock(Q.rsa);
    out.push('', 'Dastur natijasi:');
    if (R.t2) out.push(`Ochiq matn     : ${pyBytes(P.word)}`, `Shifr matn(hex): ${R.t2.ct.slice(0, 64)} ...`, `Deshifrlangan  : ${pyBytes(R.t2.dec)}`, `Imzo tekshiruvi: ${R.t2.ok ? "TO'G'RI" : "NOTO'G'RI"}`);
    else out.push('  (bajarilmagan)');
    out.push('', line, '3-TOPSHIRIQ. SHA-256 va lavina effekti', line, 'Qo‘lda hisoblash:');
    qBlock(Q.sha);
    if (R.t3) {
      const h4 = Object.assign(h4Def(), { q: `Birinchi hex belgilar XOR (${R.t3.h1[0]} ⊕ ${R.t3.h2[0]}) — nechta bit farq?` });
      qBlock([h4], 4);
      out.push('', 'Dastur natijasi:', `Matn 1      : ${R.t3.w1}`, `SHA-256(M1) : ${R.t3.h1}`, `Matn 2      : ${R.t3.w2}`, `SHA-256(M2) : ${R.t3.h2}`, `Farqlanuvchi bitlar soni (lavina effekti): ${R.t3.diff} / 256`);
    } else out.push('', 'Dastur natijasi:', '  (bajarilmagan)');
    out.push('', line, '4-TOPSHIRIQ. Tahlil', line, (s.analysis || '(yozilmagan)').trim());
    const qs = Store.state.quiz.answers;
    const total = Object.keys(qs).length;
    const right = Object.values(qs).filter((a) => a.ok).length;
    out.push('', line, `Nazorat savollari testi: ${right} / 10 (${total} ta savolga javob berilgan)`);
    out.push(`Bajarilgan topshiriqlar: ${[1, 2, 3, 4].filter(isDone).length} / 4`);
    return out.join('\n');
  }

  function init() {
    const s = S();
    $('#stName').value = s.name || '';
    $('#stGroup').value = s.group || '';
    $('#stName').addEventListener('input', (e) => { S().name = e.target.value; Store.save(); });
    $('#stGroup').addEventListener('input', (e) => { S().group = e.target.value; Store.save(); });
    $('#labTasks').addEventListener('click', onClick);
    renderVariants();
    renderTasks();
  }

  window.Lab = {
    init, reportText, isDone,
    doneCount() { return [1, 2, 3, 4].filter(isDone).length; },
    rerender() { renderVariants(); renderTasks(); },
  };
})();
