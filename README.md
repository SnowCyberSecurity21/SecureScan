# 🔐 SecureScan

**SecureScan** — URL yoki domain xavfsizligini tekshiruvchi oddiy API servis.
U HTTPS va SSL sertifikatni tahlil qilib, saytning xavfsizlik darajasini baholaydi.

---

## ⚡ Nima qila oladi

* 🌐 Domain’dan HTTPS ishlashini tekshiradi
* 🔒 SSL sertifikatni tahlil qiladi (issuer, muddati, self-signed)
* 🧠 Sertifikat domen bilan mosligini tekshiradi
* 📊 Xavfsizlik ballini hisoblaydi (0–100)

---

## 📦 Loyiha tuzilmasi

```
securescan/
├── app/
│   └── main.py
├── data/
│   └── scan_results.csv
├── venv/
```

---

## ⚙️ O‘rnatish

```bash
git clone https://github.com/SnowCyberSecurity21/SecureScan.git
cd SecureScan

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## ▶️ Ishga tushirish

```bash
uvicorn app.main:app --reload
```

Keyin brauzerda oching:

```
http://127.0.0.1:8000/docs
```

---

## 🔎 Qanday ishlatish

### Endpoint:

```
GET /scan
```

### Misol:

```
http://127.0.0.1:8000/scan?url=https://google.com
```

---

## 📊 Natija namunasi

```json
{
  "domain": "google.com",
  "final_protocol": "https",
  "checks": {
    "Real HTTPS": true,
    "SSL analysis": {
      "issuer": "Google Trust Services",
      "days_left": 80,
      "self_signed": false
    }
  },
  "security_score": 100
}
```

---

## ⚠️ Eslatma

* API yoki JSON qaytaradigan saytlar noto‘g‘ri baholanishi mumkin
* Faqat HTTPS + SSL asosida tekshiradi (chuqur phishing analiz yo‘q)

---
