import json

import requests

BASE_URL = "http://127.0.0.1:8000"


def _pretty(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def test_health() -> bool:
    """Check server health. Returns True if server is up."""
    url = f"{BASE_URL}/health"
    try:
        response = requests.get(url, timeout=10)
        print(f"[Health] status: {response.status_code} | body: {response.json()}")
        return response.status_code == 200
    except requests.RequestException as exc:
        print(f"[Health] Serverga ulanishda xatolik: {exc}")
        print("  → Serverni ishga tushiring: uvicorn app.main:app --reload")
        return False


def test_analyze(
    file_path: str = "alert.json",
    max_lines: int = 50,
    send_telegram: bool = False,
) -> None:
    """
    POST /analyze chaqiradi va natijani chop etadi.

    send_telegram=False by default — .env da token bo'lmasa xatolik bermaslik uchun.
    """
    url = f"{BASE_URL}/analyze"
    payload = {
        "file_path": file_path,
        "max_lines": max_lines,
        "send_telegram": send_telegram,
    }

    print(f"\n[Analyze] So'rov: {_pretty(payload)}")

    try:
        response = requests.post(url, json=payload, timeout=30)
    except requests.RequestException as exc:
        print(f"[Analyze] So'rovda xatolik: {exc}")
        return

    print(f"[Analyze] status: {response.status_code}")

    try:
        body = response.json()
    except ValueError:
        print(f"[Analyze] JSON parse xatosi. Raw response:\n{response.text}")
        return

    # --- Summary ---
    if response.status_code == 200:
        print(f"\n✅ Jami loglar      : {body.get('total_logs')}")
        print(f"⚠️  Shubhali holatlar: {body.get('suspicious_count')}")
        print(f"📨 Telegram yuborildi: {body.get('telegram_sent')}")

        telegram_error = body.get("telegram_error")
        if telegram_error:
            print(f"\n⚠️  Telegram xatosi: {telegram_error}")
            if "chat not found" in telegram_error.lower():
                print("   Maslahat: botga Telegramda /start yuboring va to'g'ri chat_id ni o'rnating.")
            elif "sozlanmagan" in telegram_error.lower():
                print("   Maslahat: .env faylda TELEGRAM_BOT_TOKEN va TELEGRAM_CHAT_ID ni o'rnating.")

        items = body.get("suspicious_items", [])
        if items:
            print(f"\n--- Shubhali holatlar ({len(items)} ta) ---")
            for i, item in enumerate(items, start=1):
                print(f"\n  {i}. [{item.get('timestamp', 'N/A')}]")
                print(f"     Rule level : {item.get('rule_level')}")
                print(f"     Score      : {item.get('anomaly_score')}")
                print(f"     Sabablar   : {', '.join(item.get('reasons', []))}")
                print(f"     Xabar      : {item.get('message', '')[:100]}")
        else:
            print("\n✅ Shubhali holatlar topilmadi.")
    else:
        # Server error — full body ni ko'rsat
        print(f"\n❌ Xatolik:\n{_pretty(body)}")


if __name__ == "__main__":
    if test_health():
        test_analyze(file_path="alert.json", max_lines=50, send_telegram=True)