import httpx


class TelegramApiError(RuntimeError):
    pass


class TelegramAlertClient:
    def __init__(self, bot_token: str | None, chat_id: str | None):
        self.bot_token = bot_token
        self.chat_id = chat_id

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    async def send_message(self, text: str) -> None:
        if not self.enabled:
            raise ValueError("Telegram token/chat_id sozlanmagan")

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload)
            if response.is_error:
                description = _extract_telegram_error(response)
                raise TelegramApiError(
                    f"Telegram API xatosi ({response.status_code}): {description}"
                )


def _extract_telegram_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text

    if isinstance(payload, dict) and payload.get("description"):
        return str(payload["description"])
    return response.text