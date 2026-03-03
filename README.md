# FastAPI + Wazuh Log AI Analyzer + Telegram Alert

Bu servis Wazuh loglarini o'qiydi, `scikit-learn` asosida anomaliyalarni topadi va shubhali holatlarni Telegram botga yuboradi.

## 1. O'rnatish

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

`.env` ichida quyidagilarni to'ldiring:
- `WAZUH_LOG_PATH` - Wazuh log fayl yo'li
- `TELEGRAM_BOT_TOKEN` - Telegram bot token
- `TELEGRAM_CHAT_ID` - alert keladigan chat ID

## 2. Ishga tushirish

```powershell
uvicorn app.main:app --reload
```

## 3. Endpointlar

- `GET /health` - servis holatini tekshiradi
- `POST /analyze` - loglarni tahlil qiladi va xohlasangiz Telegramga yuboradi

## 4. So'rov namunasi

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "C:/Program Files (x86)/ossec-agent/active-response/alerts.json",
    "max_lines": 700,
    "send_telegram": true
  }'
```

## 5. Tahlil qanday ishlaydi

- JSON loglar uchun Wazuh `rule.level`, `rule.description`, `agent.name`, `data.srcip/dstip` maydonlari olinadi.
- `IsolationForest` modeli matnli featuralar asosida anomaliyani aniqlaydi.
- Qo'shimcha qoidalar:
  - yuqori `rule.level` (default `>=10`)
  - xabar ichida shubhali kalit so'zlar (`failed`, `attack`, `malware`, ...)
- Top shubhali loglar Telegramga yuboriladi.

## 6. Eslatma

- Kichik log to'plamida (`<20`) model qismi ishonchli bo'lmagani uchun qoida asosidagi tahlil ustun ishlaydi.
- Agar Telegram sozlanmagan bo'lsa, API natijasi qaytadi, lekin yuborish bo'lmaydi.

