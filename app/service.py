import logging
from dataclasses import asdict
from app.analyzer import SklearnLogAnalyzer
from app.config import Settings
from app.log_parser import parse_lines, read_last_lines
from app.schemas import AnalyzeResponse, SuspiciousItem
from app.telegram_client import TelegramAlertClient

logger = logging.getLogger(__name__)


class LogAnalysisService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.analyzer = SklearnLogAnalyzer(
            contamination=settings.contamination,
            min_rule_level_alert=settings.min_rule_level_alert,
        )
        self.telegram = TelegramAlertClient(
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
        )

    async def analyze_file(
            self,
            file_path: str | None = None,
            max_lines: int | None = None,
            send_telegram: bool | None = None,
    ) -> AnalyzeResponse:
        path = file_path or self.settings.wazuh_log_path
        max_lines_value = max_lines or self.settings.default_max_lines
        should_send = self.settings.send_telegram_by_default if send_telegram is None else send_telegram

        lines = read_last_lines(path, max_lines=max_lines_value)
        events = parse_lines(lines)
        analyzed_items = self.analyzer.analyze(events)

        suspicious_items = [
            SuspiciousItem(
                timestamp=item.event.timestamp,
                source=item.event.source,
                message=item.event.message,
                reasons=item.reasons,
                anomaly_score=round(item.anomaly_score, 4),
                rule_level=item.event.rule_level,
                metadata=asdict(item.event).get("metadata", {}),
            )
            for item in analyzed_items[:20]
        ]

        telegram_sent = False
        telegram_error: str | None = None

        if should_send and suspicious_items:
            message = self._format_alert(path=path, total_logs=len(events), items=suspicious_items)
            try:
                await self.telegram.send_message(message)
                telegram_sent = True
            except Exception as exc:
                telegram_error = str(exc)
                logger.error(f"Telegram yuborishda xatolik: {telegram_error}")

        return AnalyzeResponse(
            total_logs=len(events),
            suspicious_count=len(analyzed_items),
            suspicious_items=suspicious_items,
            telegram_sent=telegram_sent,
            telegram_error=telegram_error,
        )

    def _format_alert(self, path: str, total_logs: int, items: list[SuspiciousItem]) -> str:
        """Telegram uchun chiroyli HTML formatida xabar yasaymiz"""
        top = items[:5]  # Faqat eng xavfli 5 tasini yuboramiz (Telegram xabari juda uzun bo'lib ketmasligi uchun)

        lines = [
            "🚨 <b>Wazuh AI Hujum Xabarnomasi</b> 🚨",
            f"📁 <b>Fayl:</b> <code>{path}</code>",
            f"📊 <b>Jami tahlil qilingan loglar:</b> {total_logs}",
            f"⚠️ <b>Shubhali holatlar:</b> {len(items)}",
            "",
            "🔴 <b>Eng xavfli holatlar (TOP 5):</b>",
            ""
        ]

        for idx, item in enumerate(top, start=1):
            time_str = item.timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.timestamp else "Noma'lum vaqt"
            reasons_str = ", ".join(item.reasons)
            # Log xabaridan HTML teglarni tozalaymiz (agar bo'lsa) va xavfsiz ko'rinishga keltiramiz
            safe_msg = item.message.replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")[:150]

            lines.append(f"<b>{idx}. Vaqt:</b> {time_str}")
            lines.append(f"<b>Sabablar:</b> {reasons_str}")
            if item.rule_level:
                lines.append(f"<b>Xavflilik darajasi (Rule Level):</b> {item.rule_level}")
            lines.append(f"<b>Log xabari:</b> <code>{safe_msg}...</code>")
            lines.append("—" * 20)

        return "\n".join(lines)