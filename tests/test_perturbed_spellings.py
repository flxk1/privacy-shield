import pytest

from privacy_shield.identifiers import compact_view
from privacy_shield.runner import scan


@pytest.mark.parametrize("text, hidden", [
    ("Tel. ０１７１ ２３４５６７８", "２３４５６７８"),
    ("Tel. 0171​2345678", "2345678"),
    ("Mobil: +49 171 2345678", "2345678"),
    ("Steuer-ID: 12​345​678​901", "678"),
    ("Herr Jürgen Müller kommt.", "rgen"),
    ("Frau Er​ika Muster​mann ruft an.", "mann"),
    ("Sehr geehrte Frau Joséfa Weiß,", "fa"),
])
def test_an_altered_spelling_is_masked_whole(text, hidden):
    assert hidden not in scan(text).documents[0].overlay


@pytest.mark.parametrize("text", ["Sehr geehrte Frau Joséfa Weiß,", "Herr Łukasz Wiśniewski kommt."])
def test_a_name_with_a_non_german_letter_is_not_cut(text):
    overlay = scan(text).documents[0].overlay
    assert "fa" not in overlay.split("Frau")[-1] and "ukasz" not in overlay and "niewski" not in overlay


def test_plain_text_takes_the_plain_path():
    assert compact_view("Herr Müller, Tel. 0171 2345678") is None


def test_a_circled_letter_is_not_folded():
    assert compact_view("Ⓐ") is None


@pytest.mark.parametrize("text, hidden", [
    ("SV-Nummer: 150​706​49C​103", "103"),
    ("SV-Nummer: １５０７０６４９Ｃ１０３", "１０３"),
    ("Kennzeichen B-​AB 1234", "1234"),
    ("Tel. ＋４９ ３０ １２３４５６７８", "＋"),
    ("Herr Nguyễn Văn An unterschreibt.", "ễn"),
    ("Frau Trần Thị Hoa kommt.", "ần"),
])
def test_the_later_finders_read_the_view_too(text, hidden):
    assert hidden not in scan(text).documents[0].overlay
