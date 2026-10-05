/* Bosh sahifa: bitta so‘z — uchta algoritm, jonli */
(function () {
  'use strict';
  const { $, scramble, debounce } = UI;
  const WORDS = ['encryption', 'authentication', 'security', 'cryptanalysis', 'steganography', 'password', 'blockchain', 'ciphertext', 'plaintext', 'algorithm', 'cybersecurity', 'Toshkent', 'salom'];

  function ensureKeys() {
    const h = Store.state.hero;
    if (!h.key || h.key.length !== 64) { h.key = K.toHex(K.randBytes(32)); h.iv = K.toHex(K.randBytes(16)); Store.save(); }
  }

  function render(animate) {
    ensureKeys();
    const h = Store.state.hero;
    const text = h.text;
    const bytes = K.enc.encode(text);
    const aes = K.toHex(K.AES.cbcEncrypt(bytes, K.fromHex(h.key), K.fromHex(h.iv)).ct);
    const rsa = Array.from(bytes, (b) => K.RSA.modPow(b, 17, 3233).toString()).join(' ');
    const sha = K.SHA.sha256Hex(text);
    const set = (el, v, pool) => (animate ? scramble(el, v, { pool }) : (el.textContent = v));
    set($('#laneAes'), aes);
    set($('#laneRsa'), rsa || '—', '0123456789');
    set($('#laneSha'), sha);
    $('#laneAesLen').textContent = `${bytes.length} bayt → ${aes.length / 2} bayt`;
  }

  function init() {
    const inp = $('#heroInput');
    inp.value = Store.state.hero.text;
    const upd = debounce(() => { Store.state.hero.text = inp.value; Store.save(); render(true); }, 120);
    inp.addEventListener('input', upd);
    $('#heroRandom').addEventListener('click', () => {
      let w; do { w = WORDS[(Math.random() * WORDS.length) | 0]; } while (w === inp.value);
      inp.value = w; Store.state.hero.text = w; Store.save(); render(true);
    });
    render(false);
  }
  window.Home = { init, onShow() { render(true); } };
})();
