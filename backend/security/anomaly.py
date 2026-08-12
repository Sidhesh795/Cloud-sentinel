from dataclasses import dataclass
from pathlib import Path
import pickle

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    IsolationForest = None


FEATURES = [
    "requests_per_minute",
    "data_download_mb",
    "failed_logins",
    "unique_applications",
    "access_frequency",
    "login_hour",
]

NORMAL_BASELINE = [
    [18, 42, 0, 2, 4, 9],
    [20, 50, 0, 2, 5, 10],
    [22, 55, 0, 3, 5, 11],
    [16, 35, 0, 2, 4, 14],
    [24, 65, 1, 3, 6, 15],
    [19, 48, 0, 2, 5, 16],
    [21, 52, 0, 2, 5, 10],
    [25, 70, 1, 3, 7, 13],
]

MODEL_PATH = Path(__file__).resolve().parents[2] / "ml" / "model.pkl"


@dataclass(frozen=True)
class AnomalyAssessment:
    is_anomaly: bool
    anomaly_score: float
    behavior_risk: int
    reason: str


def telemetry_to_features(telemetry) -> list[float]:
    return [
        float(telemetry.requests_per_minute),
        float(telemetry.data_download_mb),
        float(telemetry.failed_logins),
        float(telemetry.unique_applications),
        float(telemetry.access_frequency),
        float(telemetry.login_hour),
    ]


def train_model():
    if IsolationForest is None:
        return None
    model = IsolationForest(contamination=0.15, random_state=42)
    model.fit(NORMAL_BASELINE)
    return model


def save_model(path: Path = MODEL_PATH) -> Path:
    model = train_model()
    if model is None:
        raise RuntimeError("scikit-learn is required to train the anomaly model")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as model_file:
        pickle.dump(model, model_file)
    return path


def load_model():
    if IsolationForest is None or not MODEL_PATH.exists():
        return None
    with MODEL_PATH.open("rb") as model_file:
        return pickle.load(model_file)


def heuristic_behavior_risk(features: list[float]) -> int:
    requests, data_mb, failed_logins, unique_apps, access_frequency, login_hour = features
    risk = 5
    if requests > 60:
        risk += 20
    if requests > 120:
        risk += 20
    if data_mb > 200:
        risk += 15
    if data_mb > 600:
        risk += 20
    if failed_logins >= 3:
        risk += 15
    if unique_apps >= 5:
        risk += 10
    if access_frequency >= 20:
        risk += 10
    if login_hour < 6 or login_hour > 20:
        risk += 5
    return max(0, min(100, risk))


def behavior_risk_to_score(behavior_risk: int) -> float:
    return round(max(0, min(100, behavior_risk)) / 100, 2)


def assess_behavior(telemetry) -> AnomalyAssessment:
    features = telemetry_to_features(telemetry)
    model = load_model()
    predicted_anomaly = False

    if model is not None:
        prediction = model.predict([features])[0]
        predicted_anomaly = prediction == -1

    behavior_risk = heuristic_behavior_risk(features)
    if predicted_anomaly:
        behavior_risk = max(behavior_risk, 70)

    is_anomaly = behavior_risk >= 60
    if behavior_risk >= 70:
        reason = "Behavior significantly deviates from baseline"
    elif behavior_risk >= 30:
        reason = "Behavior is moderately unusual compared with baseline"
    else:
        reason = "Behavior is consistent with baseline"

    return AnomalyAssessment(
        is_anomaly=is_anomaly,
        anomaly_score=behavior_risk_to_score(behavior_risk),
        behavior_risk=behavior_risk,
        reason=reason,
    )
