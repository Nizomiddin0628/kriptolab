# KriptoLab — 2-amaliy ish (AES, RSA, SHA-256)

Faqat frontend: HTML + CSS + JavaScript. Backend kerak emas.

## Netlify'ga joylash
1. Netlify → **Add new site → Deploy manually**.
2. Shu papkani (index.html turgan papka) sudrab tashlang. Tamom.
   (Yoki GitHub reposiga yuklab, "Publish directory" = `.` qilib ulang.)

Lokal ochish: `index.html` ni brauzerda ikki marta bosing.

## Tuzilishi
- `index.html` — barcha bo‘limlar matni
- `css/style.css` — dizayn (yorug‘/qorong‘i rejim)
- `js/core.js` — AES, SHA-256, RSA ning sof JS realizatsiyasi (har bir qadam izi bilan)
- `js/store.js` — localStorage’da saqlash, oxirgi harakatdan keyin 30 daqiqa amal qiladi
- `js/aes-viz.js`, `js/rsa-viz.js`, `js/sha-viz.js`, `js/hybrid.js` — animatsiyali vizualizatorlar
- `js/lab.js` — 27 variantli amaliy topshiriq va hisobot
- `js/quiz.js` — nazorat savollari

Saqlash muddatini o‘zgartirish: `js/store.js` dagi `TTL` qiymati.
