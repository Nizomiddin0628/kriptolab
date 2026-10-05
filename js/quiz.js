/* Nazorat savollari: 5 savol × 2 test + to‘liq javob */
(function () {
  'use strict';
  const { $, $$, esc } = UI;
  const DATA = [
    {
      title: '1. Simmetrik va asimmetrik shifrlash orasidagi asosiy farq nimada?',
      full: `<p><b>Simmetrik</b> usulda shifrlash va ochish uchun bitta umumiy kalit ishlatiladi (AES). Afzalligi — juda tez va katta hajmdagi ma’lumotga mos; kamchiligi — kalitni ikkinchi tomonga xavfsiz yetkazish kerak.</p>
        <p><b>Asimmetrik</b> usulda o‘zaro bog‘langan ikki kalit bor: ochiq va yopiq (RSA). Afzalligi — kalitni xavfsiz almashish mumkin, raqamli imzo imkoni bor; kamchiligi — sekin ishlaydi va kalitlari uzun (2048 bit).</p>`,
      qs: [
        { q: 'Simmetrik shifrlashning asosiy kamchiligi nima?', o: ['Juda sekin ishlaydi', 'Kalitni tomonlarga xavfsiz yetkazish qiyin', 'Shifr matnni hech qachon ochib bo‘lmaydi', 'Faqat matn bilan ishlaydi'], a: 1, ex: 'Ikkala tomonda bir xil maxfiy kalit bo‘lishi kerak. Uni ochiq kanal orqali yuborib bo‘lmaydi — shuning uchun asimmetrik usul (RSA) kerak.' },
        { q: 'Aziza sizga maxfiy xabar yubormoqchi. U xabarni qaysi kalit bilan shifrlaydi?', o: ['Azizaning yopiq kaliti', 'Sizning ochiq kalitingiz', 'Sizning yopiq kalitingiz', 'Azizaning ochiq kaliti'], a: 1, ex: 'Qabul qiluvchining ochiq kaliti bilan shifrlanadi — shunda faqat qabul qiluvchining yopiq kaliti uni ocha oladi.' },
      ],
    },
    {
      title: '2. AES da kalit uzunligi (128, 192, 256 bit) kriptobardoshlilikka qanday ta’sir qiladi?',
      full: `<p>Kalit qanchalik uzun bo‘lsa, uni hamma variantni sinab topish (brute-force) shunchalik qiyin: 128 bitli kalitda 2¹²⁸ ta, 192 bitlida 2¹⁹² ta, 256 bitlida 2²⁵⁶ ta variant bor. Har bir qo‘shimcha bit variantlar sonini 2 barobar oshiradi.</p>
        <p>Shuning uchun AES-256 eng bardoshli variant hisoblanadi — amaliy ishda ham aynan AES-256 ishlatilgan.</p>`,
      qs: [
        { q: 'AES blokining uzunligi necha bit?', o: ['64', '128', '192', '256'], a: 1, ex: 'Blok doim 128 bit (16 bayt). 128, 192, 256 — bu kalit uzunligi variantlari.' },
        { q: 'Kalit 128 bitdan 256 bitga uzaytirilsa, brute-force uchun variantlar soni necha marta oshadi?', o: ['2 marta', '128 marta', '2¹²⁸ marta', '256 marta'], a: 2, ex: '2²⁵⁶ / 2¹²⁸ = 2¹²⁸ — bu taxminan 3,4·10³⁸ marta ko‘p.' },
      ],
    },
    {
      title: '3. RSA xavfsizligi qaysi masalaga asoslangan? Kalitlar qanday hosil qilinadi?',
      full: `<p>RSA <b>katta sonni tub ko‘paytuvchilarga ajratish (faktorlash)</b> masalasining qiyinligiga asoslangan: n = p·q ni hisoblash oson, n dan p va q ni topish esa 2048 bitli son uchun amalda imkonsiz.</p>
        <p>Kalit hosil qilish: 1) ikki katta tub son p, q tanlanadi; 2) n = p·q; 3) φ(n) = (p−1)(q−1); 4) φ(n) bilan o‘zaro tub e tanlanadi (odatda 65537); 5) d esa e·d ≡ 1 (mod φ(n)) shartidan topiladi. Ochiq kalit — (e, n), yopiq kalit — (d, n).</p>`,
      qs: [
        { q: 'RSA xavfsizligi qaysi masalaga asoslangan?', o: ['Diskret logarifm', 'Katta sonni tub ko‘paytuvchilarga ajratish', 'Xesh kolliziyasini topish', 'Chiziqli tenglamalar sistemasi'], a: 1, ex: 'RSA n = p·q ni qaytadan p va q ga ajratish (faktorlash) qiyinligiga tayanadi.' },
        { q: 'p = 5, q = 11, e = 3 bo‘lsa, d nechaga teng?', o: ['27', '13', '7', '37'], a: 0, ex: 'φ = 4·10 = 40. 3·27 = 81 = 2·40 + 1, demak 3·27 ≡ 1 (mod 40) → d = 27.' },
      ],
    },
    {
      title: '4. Xesh funksiyaning uchta asosiy xususiyatini tushuntiring.',
      full: `<p><b>Bir tomonlamalik:</b> H(M) berilgan bo‘lsa, M ni topish amalda imkonsiz — faqat hamma variantni sinash mumkin.</p>
        <p><b>Kolliziyaga chidamlilik:</b> H(M1) = H(M2) bo‘ladigan ikki xil xabarni topish amalda imkonsiz.</p>
        <p><b>Lavina effekti:</b> kirishdagi bitta bit o‘zgarsa, chiqishdagi bitlarning taxminan yarmi o‘zgaradi. Shuning uchun o‘xshash matnlarning xeshlari ham butunlay boshqacha.</p>`,
      qs: [
        { q: '“Kirishdagi 1 bit o‘zgarsa, chiqishning ~50% biti o‘zgaradi” — bu qaysi xususiyat?', o: ['Bir tomonlamalik', 'Kolliziyaga chidamlilik', 'Lavina effekti', 'Determinizm'], a: 2, ex: 'Amaliy ishda “cybersecurity” va “Cybersecurity” xeshlari 256 bitdan 134 tasida farq qilgan.' },
        { q: 'SHA-256 ga 1 bayt ham, 1 GB ham bersangiz, natija uzunligi qanday bo‘ladi?', o: ['Kirish uzunligiga proporsional', 'Doim 256 bit', '1 bayt uchun 8 bit', 'Doim 512 bit'], a: 1, ex: 'H: {0,1}* → {0,1}²⁵⁶ — kirish ixtiyoriy uzunlikda, natija doim 256 bit (64 hex belgi).' },
      ],
    },
    {
      title: '5. Nega amalda gibrid kriptotizim (masalan, TLS) afzal?',
      full: `<p>Har bir usulning kuchli tomoni boshqasining zaifligini yopadi. Simmetrik shifr tez, lekin kalitni yetkazish muammosi bor; asimmetrik shifr kalitni xavfsiz yetkazadi va imzo beradi, lekin sekin; xesh yaxlitlikni ta’minlaydi.</p>
        <p>Gibrid tizimda katta ma’lumot AES bilan shifrlanadi, faqat qisqa AES kaliti asimmetrik usul bilan yetkaziladi, yaxlitlik va imzo uchun SHA-256 ishlatiladi. TLS (HTTPS) protokoli aynan shunday ishlaydi.</p>`,
      qs: [
        { q: 'Gibrid tizimda RSA odatda nimani shifrlaydi?', o: ['Butun faylni', 'Qisqa tasodifiy AES kalitini (imzoda esa xeshni)', 'Faqat IV ni', 'Hech narsani'], a: 1, ex: 'RSA sekin va katta ma’lumotni shifrlashga mos emas. Shuning uchun u faqat qisqa AES kalitini shifrlaydi.' },
        { q: 'HTTPS (TLS) da sahifa ma’lumotlari asosan nima bilan shifrlanadi?', o: ['RSA', 'SHA-256', 'AES (simmetrik shifr)', 'Hech nima bilan'], a: 2, ex: 'Asosiy ma’lumot tez ishlaydigan simmetrik shifr (AES) bilan shifrlanadi. SHA-256 shifrlamaydi — u xeshlaydi.' },
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
