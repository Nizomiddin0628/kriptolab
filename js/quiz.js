/* Nazorat savollari: 5 savol × 2 test + to‘liq javob */
(function () {
  'use strict';
  const { $, $$, esc } = UI;
  const DATA = [
    {
      title: '1. Simmetrik va asimmetrik shifrlash orasidagi asosiy farq nimada?',
      full: `<p><b>Simmetrik</b> usulda shifrlash va ochish uchun bitta umumiy kalit ishlatiladi (AES). Afzalligi — juda tez va katta hajmga mos; kamchiligi — kalitni tomonlarga xavfsiz yetkazish kerak, n ta foydalanuvchi uchun n(n−1)/2 ta kalit kerak bo‘ladi.</p>
        <p><b>Asimmetrik</b> usulda o‘zaro bog‘langan ikki kalit bor: ochiq va yopiq (RSA). Afzalligi — kalit almashish muammosi yo‘q, raqamli imzo imkoni bor; kamchiligi — yuzlab-minglab marta sekin va kalitlari uzun (2048 bit).</p>`,
      qs: [
        { q: 'Simmetrik shifrlashning asosiy kamchiligi nima?', o: ['Juda sekin ishlaydi', 'Kalitni tomonlarga xavfsiz yetkazish qiyin', 'Shifr matnni hech qachon ochib bo‘lmaydi', 'Faqat matn bilan ishlaydi'], a: 1, ex: 'Ikkala tomonda bir xil maxfiy kalit bo‘lishi kerak. Uni ochiq kanal orqali yuborib bo‘lmaydi — shuning uchun RSA yoki Diffie-Hellman kerak.' },
        { q: 'Aziza sizga maxfiy xabar yubormoqchi. U xabarni qaysi kalit bilan shifrlaydi?', o: ['Azizaning yopiq kaliti', 'Sizning ochiq kalitingiz', 'Sizning yopiq kalitingiz', 'Azizaning ochiq kaliti'], a: 1, ex: 'Qabul qiluvchining ochiq kaliti bilan shifrlanadi — shunda faqat qabul qiluvchining yopiq kaliti uni ocha oladi.' },
      ],
    },
    {
      title: '2. AES da kalit uzunligi (128, 192, 256 bit) kriptobardoshlilikka qanday ta’sir qiladi?',
      full: `<p>Kalit uzunligi to‘liq tanlash (brute-force) hujumi uchun variantlar sonini belgilaydi: 2¹²⁸, 2¹⁹², 2²⁵⁶. Har bir qo‘shimcha bit ishni ikki barobar oshiradi. Bundan tashqari raundlar soni ham ortadi: 10, 12, 14.</p>
        <p>AES-128 ham bugun klassik kompyuterlar uchun yetarli. Ammo kvant kompyuterdagi Grover algoritmi qidiruvni kvadrat ildizgacha qisqartiradi (2¹²⁸ → 2⁶⁴), shuning uchun uzoq muddatli himoya uchun <b>AES-256</b> tavsiya etiladi — u kvant davrida ham ~128 bit xavfsizlik beradi.</p>`,
      qs: [
        { q: 'AES-256 da nechta raund bajariladi?', o: ['10', '12', '14', '16'], a: 2, ex: 'Raundlar soni Nr = Nk + 6: AES-128 → 10, AES-192 → 12, AES-256 → 14.' },
        { q: 'Kalit 128 bitdan 256 bitga uzaytirilsa, brute-force uchun variantlar soni necha marta oshadi?', o: ['2 marta', '128 marta', '2¹²⁸ marta', '256 marta'], a: 2, ex: '2²⁵⁶ / 2¹²⁸ = 2¹²⁸ — bu taxminan 3,4·10³⁸ marta ko‘p.' },
      ],
    },
    {
      title: '3. RSA xavfsizligi qaysi masalaga asoslangan? Kalitlar qanday hosil qilinadi?',
      full: `<p>RSA <b>katta sonni tub ko‘paytuvchilarga ajratish (faktorlash)</b> masalasining qiyinligiga asoslangan: n = p·q ni hisoblash oson, n dan p va q ni topish esa 2048 bitli son uchun amalda imkonsiz.</p>
        <p>Kalit hosil qilish: 1) ikki katta tub son p, q tanlanadi; 2) n = p·q; 3) φ(n) = (p−1)(q−1); 4) gcd(e, φ) = 1 bo‘lgan e tanlanadi (odatda 65537); 5) e·d ≡ 1 (mod φ) dan d kengaytirilgan Evklid algoritmi bilan topiladi. Ochiq kalit — (e, n), yopiq kalit — (d, n).</p>`,
      qs: [
        { q: 'RSA xavfsizligi qaysi masalaga asoslangan?', o: ['Diskret logarifm', 'Katta sonni tub ko‘paytuvchilarga ajratish', 'Xesh kolliziyasini topish', 'Chiziqli tenglamalar sistemasi'], a: 1, ex: 'Diskret logarifm — Diffie-Hellman va DSA asosi. RSA esa faktorlashga tayanadi.' },
        { q: 'p = 5, q = 11, e = 3 bo‘lsa, d nechaga teng?', o: ['27', '13', '7', '37'], a: 0, ex: 'φ = 4·10 = 40. 3·27 = 81 = 2·40 + 1, demak 3·27 ≡ 1 (mod 40) → d = 27.' },
      ],
    },
    {
      title: '4. Xesh funksiyaning uchta asosiy xususiyatini tushuntiring.',
      full: `<p><b>Bir tomonlamalik:</b> H(M) berilgan bo‘lsa, M ni topish amalda imkonsiz — faqat hamma variantni sinash mumkin.</p>
        <p><b>Kolliziyaga chidamlilik:</b> H(M1) = H(M2) bo‘ladigan ikki xil xabarni topish amalda imkonsiz. MD5 va SHA-1 aynan shu xususiyatni yo‘qotgani uchun eskirgan.</p>
        <p><b>Lavina effekti:</b> kirishdagi bitta bit o‘zgarsa, chiqishdagi bitlarning taxminan yarmi o‘zgaradi. Shuning uchun o‘xshash matnlarning xeshlari ham butunlay boshqacha.</p>`,
      qs: [
        { q: '“Kirishdagi 1 bit o‘zgarsa, chiqishning ~50% biti o‘zgaradi” — bu qaysi xususiyat?', o: ['Bir tomonlamalik', 'Kolliziyaga chidamlilik', 'Lavina effekti', 'Determinizm'], a: 2, ex: 'Amaliy ishda “cybersecurity” va “Cybersecurity” xeshlari 256 bitdan 134 tasida farq qilgan.' },
        { q: 'SHA-256 ga 1 bayt ham, 1 GB ham bersangiz, natija uzunligi qanday bo‘ladi?', o: ['Kirish uzunligiga proporsional', 'Doim 256 bit', '1 bayt uchun 8 bit', 'Doim 512 bit'], a: 1, ex: 'H: {0,1}* → {0,1}²⁵⁶. 512 bit — bu ichki blok o‘lchami, natija emas.' },
      ],
    },
    {
      title: '5. Nega amalda gibrid kriptotizim (masalan, TLS) afzal?',
      full: `<p>Har bir usulning kuchli tomoni boshqasining zaifligini yopadi. Simmetrik shifr tez, lekin kalit yetkazish muammosi bor; asimmetrik shifr kalitni xavfsiz yetkazadi va imzo beradi, lekin sekin; xesh yaxlitlikni ta’minlaydi.</p>
        <p>Gibrid tizimda katta ma’lumot AES bilan shifrlanadi, faqat qisqa AES kaliti asimmetrik usul bilan uzatiladi (yoki ECDHE bilan kelishiladi), imzo va yaxlitlik uchun SHA-256 ishlatiladi. TLS 1.3 (HTTPS) aynan shunday ishlaydi: ECDHE + AES-GCM + RSA/ECDSA sertifikat imzosi + SHA-256/384.</p>`,
      qs: [
        { q: 'Gibrid tizimda RSA odatda nimani shifrlaydi?', o: ['Butun faylni', 'Qisqa tasodifiy AES kalitini (imzoda esa xeshni)', 'Faqat IV ni', 'Hech narsani'], a: 1, ex: 'RSA sekin va bir martada ≈190 baytdan ko‘p shifrlay olmaydi (2048 bit, OAEP). Shuning uchun u faqat kalitni “o‘raydi”.' },
        { q: 'HTTPS (TLS 1.3) da sahifa ma’lumotlari asosan nima bilan shifrlanadi?', o: ['RSA', 'SHA-256', 'AES-GCM kabi simmetrik shifr', 'MD5'], a: 2, ex: 'Asosiy oqim simmetrik shifr (AES-GCM yoki ChaCha20-Poly1305) bilan shifrlanadi. SHA-256 shifrlamaydi — u xeshlaydi.' },
      ],
    },
  ];

  const S = () => Store.state.quiz;

  function render() {
    const ans = S().answers;
    let html = '';
    DATA.forEach((sec, si) => {
      html += `<h3 style="margin-top:${si ? 28 : 0}px">${esc(sec.title)}</h3>`;
      sec.qs.forEach((q, qi) => {
        const id = `${si}_${qi}`;
        const a = ans[id];
        html += `<div class="quiz-q${a ? ' answered' : ''}" data-id="${id}"><div class="qt">${esc(q.q)}</div><div class="opts">` +
          q.o.map((o, oi) => {
            let cls = '';
            if (a) { if (oi === q.a) cls = 'right'; else if (oi === a.pick) cls = 'wrong'; }
            return `<button data-o="${oi}" class="${cls}" ${a ? 'disabled' : ''}>${esc(o)}</button>`;
          }).join('') +
          `</div><div class="ex">${a ? (a.ok ? '<b style="color:var(--ok)">To‘g‘ri.</b> ' : '<b style="color:var(--bad)">Noto‘g‘ri.</b> ') : ''}${esc(q.ex)}</div></div>`;
      });
      html += `<details class="full"><summary>To‘liq javob</summary><div>${sec.full}</div></details>`;
    });
    $('#quizBox').innerHTML = html;
    const right = Object.values(ans).filter((x) => x.ok).length;
    $('#quizScore').textContent = `Natija: ${right} / 10 to‘g‘ri (${Object.keys(ans).length} ta javob)`;
  }

  function init() {
    $('#quizBox').addEventListener('click', (e) => {
      const b = e.target.closest('button[data-o]');
      if (!b) return;
      const qEl = b.closest('.quiz-q');
      const [si, qi] = qEl.dataset.id.split('_').map(Number);
      const q = DATA[si].qs[qi];
      const pick = +b.dataset.o;
      S().answers[qEl.dataset.id] = { pick, ok: pick === q.a };
      Store.save();
      render();
      App.updateProgress();
    });
    $('#quizReset').addEventListener('click', () => { S().answers = {}; Store.save(); render(); });
    render();
  }
  window.Quiz = { init, render };
})();
