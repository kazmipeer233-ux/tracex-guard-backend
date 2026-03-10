import os
from typing import Any, Dict, List, Optional

try:
    import numpy as np
    from tensorflow.lite.python.interpreter import Interpreter
except ImportError:
    np = None
    Interpreter = None

MODEL_PATH_TFLITE = "app/ai/threat_model.tflite"


class ThreatDetectionEngine:
    def __init__(self):
        self.interpreter = None
        self.input_details = None
        self.output_details = None
        self._load_model()

    def _load_model(self):
        if not Interpreter or not np:
            return

        if not os.path.exists(MODEL_PATH_TFLITE):
            return

        try:
            self.interpreter = Interpreter(model_path=MODEL_PATH_TFLITE)
            self.interpreter.allocate_tensors()
            self.input_details = self.interpreter.get_input_details()[0]
            self.output_details = self.interpreter.get_output_details()[0]
        except Exception:
            self.interpreter = None

    def predict(self, features: Dict) -> Dict:
        # When a TFLite model is available, run inference against it.
        if self.interpreter:
            return self._predict_tflite(features)

        # Fallback: simple heuristic detection
        return {
            "threat": False,
            "type": None,
            "confidence": 0.0,
            "note": "No model loaded, returning safe default",
        }

    def _predict_tflite(self, features: Dict) -> Dict:
        # Build input vector (example: fixed size feature vector)
        x = np.array([self._preprocess(features)], dtype=self.input_details.get("dtype", np.float32))
        self.interpreter.set_tensor(self.input_details["index"], x)
        self.interpreter.invoke()
        output = self.interpreter.get_tensor(self.output_details["index"])
        # Assuming output is probability vector [p_benign, p_malware, p_spyware, ...]
        probs = output[0]
        pred = int(np.argmax(probs))
        return {
            "threat": bool(pred != 0),
            "type": self._get_threat_type(pred),
            "confidence": float(np.max(probs)),
        }

    def _preprocess(self, features: Dict) -> List[float]:
        # TODO: Replace this with real feature engineering (permissions, behavior, network, signatures)
        # This placeholder simply hashes values into a fixed-length vector.
        vec = [0.0] * 64
        idx = 0
        for key in ["permissions", "behavior", "network", "signatures", "url"]:
            value = features.get(key)
            if isinstance(value, dict):
                for k, v in value.items():
                    vec[idx % len(vec)] += hash(str(k)) % 100 / 100.0
                    vec[(idx + 1) % len(vec)] += hash(str(v)) % 100 / 100.0
                    idx += 2
            elif isinstance(value, list):
                for item in value:
                    vec[idx % len(vec)] += hash(str(item)) % 100 / 100.0
                    idx += 1
            elif value is not None:
                vec[idx % len(vec)] += hash(str(value)) % 100 / 100.0
                idx += 1
        return vec

    def _get_threat_type(self, pred: int) -> str:
        mapping = {
            0: "benign",
            1: "malware",
            2: "spyware",
            3: "phishing",
            4: "suspicious_permissions",
        }
        return mapping.get(pred, "unknown")


engine = ThreatDetectionEngine()


def detect_threat(features: Dict) -> Dict:
    return engine.predict(features)
