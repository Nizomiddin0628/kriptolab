/* KriptoLab — kriptografik yadro (o‘quv maqsadida, sof JavaScript)
 * AES-128/192/256 (FIPS-197) — har bir amal izi (trace) bilan
 * SHA-256 (FIPS 180-4) — padding, xabar jadvali va 64 raund izi bilan
 * RSA (BigInt) — kengaytirilgan Evklid va kvadrat-ko‘paytirish izi bilan
 */
(function (G) {
  'use strict';

  /* ---------- umumiy yordamchilar ---------- */
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: false });
  const hex2 = (b) => b.toString(16).padStart(2, '0');
  const toHex = (arr) => Array.from(arr, hex2).join('');
  const fromHex = (h) => {
    h = (h || '').replace(/[^0-9a-f]/gi, '');
    if (h.length % 2) h = h.slice(0, -1);
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  };
  const randBytes = (n) => {
    const a = new Uint8Array(n);
    (G.crypto || require('crypto').webcrypto).getRandomValues(a);
    return a;
  };
  const bin8 = (b) => b.toString(2).padStart(8, '0');
  const popcount = (x) => { let c = 0; while (x) { c += x & 1; x >>>= 1; } return c; };

  /* =========================================================
   *  AES
   * ========================================================= */
  const SBOX = new Uint8Array(256);
  const INV_SBOX = new Uint8Array(256);
  (function initSbox() {
    const rotl8 = (x, s) => ((x << s) | (x >>> (8 - s))) & 0xff;
    let p = 1, q = 1;
    do {
      p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      const x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
      SBOX[p] = (x ^ 0x63) & 0xff;
    } while (p !== 1);
    SBOX[0] = 0x63;
    for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
  })();

  const xtime = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;
  const gmul = (a, b) => {
    let r = 0;
    while (b) { if (b & 1) r ^= a; a = xtime(a); b >>= 1; }
    return r;
  };
  const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  const MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
  const INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]];

  /* Kalit kengaytirish. words: Uint8Array[4] ro‘yxati, wtrace: har bir so‘z qanday hosil bo‘lgani */
  function expandKey(key) {
    const Nk = key.length / 4;
    if (![4, 6, 8].includes(Nk)) throw new Error('Kalit uzunligi 16, 24 yoki 32 bayt bo‘lishi kerak');
    const Nr = Nk + 6;
    const total = 4 * (Nr + 1);
    const w = [];
    const wtrace = [];
    for (let i = 0; i < Nk; i++) {
      w.push(key.slice(4 * i, 4 * i + 4));
      wtrace.push({ i, kind: 'key' });
    }
    for (let i = Nk; i < total; i++) {
      let temp = Uint8Array.from(w[i - 1]);
      const t = { i, kind: 'xor', prev: toHex(w[i - 1]), back: toHex(w[i - Nk]) };
      if (i % Nk === 0) {
        temp = Uint8Array.from([temp[1], temp[2], temp[3], temp[0]]);
        t.rot = toHex(temp);
        temp = temp.map((b) => SBOX[b]);
        t.sub = toHex(temp);
        temp[0] ^= RCON[i / Nk];
        t.rcon = hex2(RCON[i / Nk]);
        t.afterRcon = toHex(temp);
        t.kind = 'rot';
      } else if (Nk > 6 && i % Nk === 4) {
        temp = temp.map((b) => SBOX[b]);
        t.sub = toHex(temp);
        t.kind = 'sub';
      }
      const nw = new Uint8Array(4);
      for (let j = 0; j < 4; j++) nw[j] = w[i - Nk][j] ^ temp[j];
      w.push(nw);
      t.result = toHex(nw);
      wtrace.push(t);
    }
    const roundKeys = [];
    for (let r = 0; r <= Nr; r++) {
      const rk = new Uint8Array(16);
      for (let c = 0; c < 4; c++) rk.set(w[4 * r + c], 4 * c);
      roundKeys.push(rk);
    }
    return { Nk, Nr, words: w, wtrace, roundKeys };
  }

  /* holat: 16 bayt, ustun bo‘yicha: s[r][c] = b[r + 4c] */
  const subBytes = (s) => s.map((b) => SBOX[b]);
  const invSubBytes = (s) => s.map((b) => INV_SBOX[b]);
  function shiftRows(s) {
    const o = new Uint8Array(16);
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) o[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    return o;
  }
  function invShiftRows(s) {
    const o = new Uint8Array(16);
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) o[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
    return o;
  }
  function mixWith(s, M) {
    const o = new Uint8Array(16);
    for (let c = 0; c < 4; c++)
      for (let r = 0; r < 4; r++) {
        let v = 0;
        for (let k = 0; k < 4; k++) v ^= gmul(M[r][k], s[k + 4 * c]);
        o[r + 4 * c] = v;
      }
    return o;
  }
  const mixColumns = (s) => mixWith(s, MIX);
  const invMixColumns = (s) => mixWith(s, INV_MIX);
  const xor16 = (a, b) => { const o = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; };

  /* Bitta blokni shifrlash. trace=true bo‘lsa, har bir amal saqlanadi */
  function encryptBlock(block, ks, trace) {
    const steps = trace ? [] : null;
    let s = Uint8Array.from(block);
    const push = (round, op, before, after, extra) => {
      if (steps) steps.push(Object.assign({ round, op, before: Uint8Array.from(before), after: Uint8Array.from(after) }, extra || {}));
    };
    let n = xor16(s, ks.roundKeys[0]);
    push(0, 'addRoundKey', s, n, { roundKey: ks.roundKeys[0] });
    s = n;
    for (let r = 1; r <= ks.Nr; r++) {
      n = subBytes(s); push(r, 'subBytes', s, n); s = n;
      n = shiftRows(s); push(r, 'shiftRows', s, n); s = n;
      if (r !== ks.Nr) { n = mixColumns(s); push(r, 'mixColumns', s, n); s = n; }
      n = xor16(s, ks.roundKeys[r]); push(r, 'addRoundKey', s, n, { roundKey: ks.roundKeys[r] }); s = n;
    }
    return { out: s, steps };
  }
  function decryptBlock(block, ks) {
    let s = xor16(block, ks.roundKeys[ks.Nr]);
    for (let r = ks.Nr - 1; r >= 0; r--) {
      s = invShiftRows(s);
      s = invSubBytes(s);
      s = xor16(s, ks.roundKeys[r]);
      if (r !== 0) s = invMixColumns(s);
    }
    return s;
  }

  function pkcs7Pad(data) {
    const pad = 16 - (data.length % 16);
    const out = new Uint8Array(data.length + pad);
    out.set(data);
    out.fill(pad, data.length);
    return { out, pad };
  }
  function pkcs7Unpad(data) {
    const pad = data[data.length - 1];
    if (pad < 1 || pad > 16) throw new Error('Noto‘g‘ri padding');
    for (let i = data.length - pad; i < data.length; i++) if (data[i] !== pad) throw new Error('Noto‘g‘ri padding');
    return data.slice(0, data.length - pad);
  }

  /* CBC: har bir blok uchun to‘liq ma’lumot qaytaradi */
  function cbcEncrypt(plain, key, iv, trace) {
    const ks = expandKey(key);
    const { out: padded, pad } = pkcs7Pad(plain);
    const blocks = [];
    let prev = Uint8Array.from(iv);
    const ct = new Uint8Array(padded.length);
    for (let i = 0; i < padded.length; i += 16) {
      const p = padded.slice(i, i + 16);
      const x = xor16(p, prev);
      const { out, steps } = encryptBlock(x, ks, trace);
      ct.set(out, i);
      blocks.push({ index: i / 16, p, chainIn: prev, x, c: out, steps });
      prev = out;
    }
    return { ks, padded, pad, blocks, ct };
  }
  function cbcDecrypt(ct, key, iv) {
    const ks = expandKey(key);
    const out = new Uint8Array(ct.length);
    let prev = Uint8Array.from(iv);
    for (let i = 0; i < ct.length; i += 16) {
      const c = ct.slice(i, i + 16);
      out.set(xor16(decryptBlock(c, ks), prev), i);
      prev = c;
    }
    return pkcs7Unpad(out);
  }
  function ecbEncryptRaw(data, key) {
    const ks = expandKey(key);
    const out = new Uint8Array(data.length);
    for (let i = 0; i + 16 <= data.length; i += 16) out.set(encryptBlock(data.slice(i, i + 16), ks).out, i);
    return out;
  }
  function cbcEncryptRaw(data, key, iv) {
    const ks = expandKey(key);
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let i = 0; i + 16 <= data.length; i += 16) {
      const c = encryptBlock(xor16(data.slice(i, i + 16), prev), ks).out;
      out.set(c, i); prev = c;
    }
    return out;
  }

  /* MixColumns bitta bayt hisobi (tushuntirish uchun) */
  function mixDetail(before, r, c, inverse) {
    const M = inverse ? INV_MIX : MIX;
    const terms = [];
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const b = before[k + 4 * c];
      const prod = gmul(M[r][k], b);
      terms.push({ m: M[r][k], b, prod });
      v ^= prod;
    }
    return { terms, value: v };
  }

  /* =========================================================
   *  SHA-256
   * ========================================================= */
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const S0 = (a) => (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
  const S1 = (e) => (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
  const s0 = (x) => (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
  const s1 = (x) => (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0;
  const Ch = (e, f, g) => ((e & f) ^ (~e & g)) >>> 0;
  const Maj = (a, b, c) => ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
  const hex8 = (x) => (x >>> 0).toString(16).padStart(8, '0');

  function shaPad(msg) {
    const L = msg.length * 8;
    const k = (448 - ((L + 1) % 512) + 512) % 512;
    const total = (L + 1 + k + 64) / 8;
    const out = new Uint8Array(total);
    out.set(msg);
    out[msg.length] = 0x80;
    // 64 bitli uzunlik (big-endian)
    const hi = Math.floor(L / 0x100000000), lo = L >>> 0;
    const dv = new DataView(out.buffer);
    dv.setUint32(total - 8, hi);
    dv.setUint32(total - 4, lo);
    return { out, L, k, blocks: total / 64 };
  }

  function sha256(msgBytes, trace) {
    const { out, L, k, blocks } = shaPad(msgBytes);
    const H = H0.slice();
    const tr = trace ? { L, k, padded: out, nblocks: blocks, blocks: [] } : null;
    const dv = new DataView(out.buffer);
    for (let bi = 0; bi < blocks; bi++) {
      const W = new Uint32Array(64);
      for (let t = 0; t < 16; t++) W[t] = dv.getUint32(bi * 64 + t * 4);
      for (let t = 16; t < 64; t++) W[t] = (s1(W[t - 2]) + W[t - 7] + s0(W[t - 15]) + W[t - 16]) >>> 0;
      let [a, b, c, d, e, f, g, h] = H;
      const rounds = trace ? [] : null;
      const Hin = H.slice();
      for (let t = 0; t < 64; t++) {
        const sig1 = S1(e), ch = Ch(e, f, g), sig0 = S0(a), maj = Maj(a, b, c);
        const T1 = (h + sig1 + ch + K256[t] + W[t]) >>> 0;
        const T2 = (sig0 + maj) >>> 0;
        const before = [a, b, c, d, e, f, g, h];
        h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
        if (rounds) rounds.push({ t, before, after: [a, b, c, d, e, f, g, h], sig1, ch, sig0, maj, T1, T2, K: K256[t], W: W[t] });
      }
      const regs = [a, b, c, d, e, f, g, h];
      for (let i = 0; i < 8; i++) H[i] = (H[i] + regs[i]) >>> 0;
      if (tr) tr.blocks.push({ W: Array.from(W), rounds, Hin, regs, Hout: H.slice() });
    }
    const digest = H.map(hex8).join('');
    if (tr) tr.digest = digest;
    return trace ? tr : digest;
  }
  const sha256Hex = (str) => sha256(enc.encode(str));

  /* Tez SHA-256 (brute-force demo uchun, trace yo‘q) — sha256 bilan bir xil */
  const sha256Bytes = (bytes) => fromHex(sha256(bytes));

  function hexBitDiff(h1, h2) {
    let n = 0;
    for (let i = 0; i < Math.min(h1.length, h2.length); i++) n += popcount(parseInt(h1[i], 16) ^ parseInt(h2[i], 16));
    return n;
  }

  /* =========================================================
   *  RSA (BigInt)
   * ========================================================= */
  const B = (x) => BigInt(x);
  function isPrimeSmall(n) {
    n = Number(n);
    if (!Number.isInteger(n) || n < 2) return false;
    if (n % 2 === 0) return n === 2;
    for (let i = 3; i * i <= n; i += 2) if (n % i === 0) return false;
    return true;
  }
  function gcd(a, b) { a = B(a); b = B(b); while (b) { [a, b] = [b, a % b]; } return a; }

  /* Kengaytirilgan Evklid: e*d ≡ 1 (mod phi). Jadval qatorlarini qaytaradi */
  function egcdTrace(e, phi) {
    e = B(e); phi = B(phi);
    const rows = [];
    let r0 = phi, r1 = e, t0 = 0n, t1 = 1n;
    rows.push({ q: null, r: r0, t: t0 });
    rows.push({ q: null, r: r1, t: t1 });
    while (r1 !== 0n) {
      const q = r0 / r1;
      const r2 = r0 - q * r1;
      const t2 = t0 - q * t1;
      rows.push({ q, r: r2, t: t2 });
      [r0, r1] = [r1, r2];
      [t0, t1] = [t1, t2];
    }
    const g = r0;
    let d = null;
    if (g === 1n) d = ((t0 % phi) + phi) % phi;
    return { rows, gcd: g, d };
  }

  /* Kvadrat-ko‘paytirish (chapdan o‘ngga), har bir qadam bilan */
  function modPowTrace(base, exp, mod) {
    base = B(base); exp = B(exp); mod = B(mod);
    const bits = exp.toString(2);
    const steps = [];
    let r = 1n;
    for (let i = 0; i < bits.length; i++) {
      const sq = (r * r) % mod;
      let after = sq;
      if (bits[i] === '1') after = (sq * base) % mod;
      steps.push({ bit: bits[i], from: r, squared: sq, result: after });
      r = after;
    }
    return { bits, steps, result: r };
  }
  function modPow(base, exp, mod) {
    base = B(base) % B(mod); exp = B(exp); mod = B(mod);
    let r = 1n;
    while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; base = (base * base) % mod; exp >>= 1n; }
    return r;
  }

  const api = {
    enc, dec, toHex, fromHex, hex2, hex8, bin8, randBytes, popcount,
    AES: {
      SBOX, INV_SBOX, RCON, MIX, gmul, xtime, expandKey, encryptBlock, decryptBlock,
      subBytes, shiftRows, mixColumns, xor16, pkcs7Pad, pkcs7Unpad,
      cbcEncrypt, cbcDecrypt, ecbEncryptRaw, cbcEncryptRaw, mixDetail,
    },
    SHA: { K: K256, H0, sha256, sha256Hex, sha256Bytes, shaPad, hexBitDiff, S0, S1, s0, s1, Ch, Maj, rotr },
    RSA: { isPrimeSmall, gcd, egcdTrace, modPowTrace, modPow },
  };
  G.K = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
