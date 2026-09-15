from __future__ import annotations

import numpy as np
import pytest


def test_extract_contextual_pii_features_shape() -> None:
    from privacy_shield.onnx_contextual_pii import FEATURE_NAMES, extract_contextual_pii_features
    from privacy_shield.scanner import ScanResult, scan_text

    text = "Name: Max Muller works in Berlin. Project Horse is internal draft v2."
    regex_result = scan_text(text)
    features = extract_contextual_pii_features(text, regex_result)

    assert features.shape == (1, len(FEATURE_NAMES))
    assert features.dtype == np.float32


def test_run_contextual_pii_session_parses_score_and_label() -> None:
    from privacy_shield.onnx_contextual_pii import run_contextual_pii_session

    class _Input:
        name = "float_input"

    class _Output:
        name = "probabilities"

    class _Session:
        def get_inputs(self):
            return [_Input()]

        def get_outputs(self):
            return [_Output(), _Output()]

        def run(self, *_args, **_kwargs):
            return [np.array([[0.1, 0.82]], dtype=np.float32), ["contextual_pii"]]

    result = run_contextual_pii_session(_Session(), np.zeros((1, 16), dtype=np.float32))

    assert result["contextual_pii"] is True
    assert result["label"] == "contextual_pii"
    assert result["score"] == pytest.approx(0.82)
