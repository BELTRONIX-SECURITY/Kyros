import pytest
from kyros.soc import analyze_file, classify_domain, classify_ip

def test_public_ip():
    result = classify_ip("8.8.8.8")
    assert result["scope"] == "public"
    assert result["external_lookup"] is False

def test_private_ip():
    assert classify_ip("192.168.1.10")["scope"] == "private"

def test_invalid_ip():
    with pytest.raises(ValueError):
        classify_ip("999.1.1.1")

def test_domain_normalized():
    assert classify_domain("Example.COM")["indicator"] == "example.com"
    assert classify_domain("example.com")["external_lookup"] is False

@pytest.mark.parametrize("value", ["https://example.com", "bad_domain", ""])
def test_invalid_domain(value):
    with pytest.raises(ValueError):
        classify_domain(value)

def test_file_hashes():
    result = analyze_file(b"%PDF-1.7 sample", "sample.pdf")
    assert result["file_type"] == "PDF document"
    assert len(result["hashes"]["sha256"]) == 64
    assert result["execution_performed"] is False
    assert result["external_submission"] is False

def test_empty_file():
    with pytest.raises(ValueError):
        analyze_file(b"")


from kyros.soc import classify_email


def test_email_is_validated_locally():
    result = classify_email("Analyst@Example.COM")
    assert result["indicator"] == "Analyst@example.com"
    assert result["domain"] == "example.com"
    assert result["external_submission"] is False
    assert result["risk"] == "unknown"


@pytest.mark.parametrize("value", ["not-an-email", "a@@example.com", "a@bad_domain", "a b@example.com"])
def test_invalid_email(value):
    with pytest.raises(ValueError):
        classify_email(value)


def test_png_signature_detection():
    result = analyze_file(b"\x89PNG\r\n\x1a\ncontent", "image.png")
    assert result["file_type"] == "PNG image"
