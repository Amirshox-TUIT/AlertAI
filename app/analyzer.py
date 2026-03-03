from dataclasses import dataclass

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import HashingVectorizer

from app.log_parser import LogEvent


SUSPICIOUS_KEYWORDS = (
    "failed",
    "denied",
    "attack",
    "malware",
    "bruteforce",
    "unauthorized",
    "sql injection",
    "xss",
    "suspicious",
    "root access",
)


@dataclass(slots=True)
class AnalyzedLog:
    event: LogEvent
    anomaly_score: float
    reasons: list[str]


class SklearnLogAnalyzer:
    def __init__(self, contamination: float, min_rule_level_alert: int):
        self.contamination = contamination
        self.min_rule_level_alert = min_rule_level_alert
        self.vectorizer = HashingVectorizer(
            n_features=4096,
            alternate_sign=False,
            ngram_range=(1, 2),
            norm="l2",
            lowercase=True,
        )

    def analyze(self, events: list[LogEvent]) -> list[AnalyzedLog]:
        if not events:
            return []

        texts = [event.feature_text() for event in events]
        features = self.vectorizer.transform(texts)
        model_predictions = [1] * len(events)
        model_scores = [0.0] * len(events)

        # IsolationForest needs enough examples to separate normal/anomaly points.
        if len(events) >= 20:
            model = IsolationForest(
                n_estimators=200,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )
            model_predictions = model.fit_predict(features).tolist()
            model_scores = (-model.decision_function(features)).tolist()

        analyzed: list[AnalyzedLog] = []
        for index, event in enumerate(events):
            reasons: list[str] = []
            score = float(model_scores[index])

            if model_predictions[index] == -1:
                reasons.append("ML model anomaliya topdi")

            if event.rule_level is not None and event.rule_level >= self.min_rule_level_alert:
                reasons.append(f"Wazuh rule level yuqori: {event.rule_level}")
                score += event.rule_level / 20

            lower_msg = event.message.lower()
            matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_msg]
            if matched_keywords:
                reasons.append(f"Shubhali kalit so'zlar: {', '.join(matched_keywords)}")
                score += min(1.0, 0.2 * len(matched_keywords))

            if reasons:
                analyzed.append(AnalyzedLog(event=event, anomaly_score=score, reasons=reasons))

        analyzed.sort(key=lambda item: item.anomaly_score, reverse=True)
        return analyzed

