from __future__ import annotations

from types import SimpleNamespace


def test_privacy_shield_process_image_input(monkeypatch, tmp_path) -> None:
    from brain.privacy_shield.shield import MediaType, PrivacyShield

    image_path = tmp_path / "sample.jpg"
    image_path.write_bytes(b"\xff\xd8\xff\xe0")

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)
    shield = PrivacyShield(enable_ocr=True, enable_face_detection=True)

    fake_img_result = SimpleNamespace(
        full_text="Contact max@example.com",
        ocr_engine="tesseract",
        faces=[SimpleNamespace()],
        metadata=SimpleNamespace(pii_fields=["GPS"]),
        errors=[],
    )
    monkeypatch.setattr(shield, "_get_image_processor", lambda: SimpleNamespace(process=lambda path: fake_img_result))

    result = shield.process_file(image_path)

    assert result.input_type == MediaType.IMAGE
    assert result.extraction_method == "ocr_tesseract"
    assert result.faces_detected == 1
    assert result.metadata_pii_fields == ["GPS"]
    assert result.pii_detected is True


def test_privacy_shield_process_audio_input(monkeypatch, tmp_path) -> None:
    from brain.privacy_shield.shield import MediaType, PrivacyShield

    audio_path = tmp_path / "sample.wav"
    audio_path.write_bytes(b"RIFF....WAVEfmt ")

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)
    shield = PrivacyShield(enable_stt=True)

    fake_audio_result = SimpleNamespace(
        full_transcript="Call me on +49 151 1234567",
        stt_engine="faster-whisper",
        metadata=SimpleNamespace(pii_fields=["artist"]),
        has_transcript=True,
        errors=[],
    )
    monkeypatch.setattr(shield, "_get_audio_processor", lambda: SimpleNamespace(process=lambda path: fake_audio_result))

    result = shield.process_file(audio_path)

    assert result.input_type == MediaType.AUDIO
    assert result.extraction_method == "stt_faster-whisper"
    assert result.transcript_available is True
    assert result.metadata_pii_fields == ["artist"]
    assert result.pii_detected is True


def test_privacy_shield_process_video_input(monkeypatch, tmp_path) -> None:
    from brain.privacy_shield.shield import MediaType, PrivacyShield

    video_path = tmp_path / "sample.mp4"
    video_path.write_bytes(b"\x00\x00\x00\x18ftypmp42")

    monkeypatch.setattr(PrivacyShield, "check_local_model_available", lambda self: False)
    shield = PrivacyShield(enable_stt=True, enable_ocr=True, enable_face_detection=True)

    fake_video_result = SimpleNamespace(
        full_transcript="Supplier email jane@example.com",
        all_visual_text="IBAN DE89370400440532013000",
        total_faces_detected=2,
        metadata=SimpleNamespace(pii_fields=["gps"]),
        errors=[],
    )
    monkeypatch.setattr(shield, "_get_video_processor", lambda: SimpleNamespace(process=lambda path: fake_video_result))

    result = shield.process_file(video_path)

    assert result.input_type == MediaType.VIDEO
    assert result.extraction_method == "video_multimodal"
    assert "jane@example.com" in result.extracted_text
    assert "DE89370400440532013000" in result.extracted_text
    assert result.faces_detected == 2
    assert result.metadata_pii_fields == ["gps"]
    assert result.pii_detected is True
