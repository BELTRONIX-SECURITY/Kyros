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
    result = analyze_file(bytes([137, 80, 78, 71, 13, 10, 26, 10]) + b"content", "image.png")
    assert result["file_type"] == "PNG image"


def test_yara_reports_not_configured_without_external_submission(monkeypatch):
    monkeypatch.delenv("KYROS_YARA_RULES", raising=False)
    from kyros.soc import scan_yara
    result = scan_yara(b"sample bytes")
    assert result["status"] == "not_configured"
    assert result["matches"] == []


def test_xlsx_is_identified_and_inspected_without_execution():
    from io import BytesIO
    from openpyxl import Workbook

    stream = BytesIO()
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Alertas"
    sheet["A1"] = "Indicador"
    sheet["A2"] = "8.8.8.8"
    sheet["B2"] = "=1+1"
    workbook.save(stream)

    result = analyze_file(stream.getvalue(), "alertas.xlsx")
    assert result["file_type"] == "Microsoft Excel (XLSX)"
    assert result["structure"]["valid_ooxml"] is True
    assert result["structure"]["sheet_count"] == 1
    assert result["structure"]["formulas_present"] is True
    assert result["structure"]["formula_count"] == 1
    assert result["structure"]["extension_matches_structure"] is True
    assert result["execution_performed"] is False
    assert result["external_submission"] is False


def test_xlsx_extension_mismatch_is_reported():
    from io import BytesIO
    from openpyxl import Workbook

    stream = BytesIO()
    Workbook().save(stream)
    result = analyze_file(stream.getvalue(), "documento.docx")
    assert result["file_type"] == "Microsoft Excel (XLSX)"
    assert result["structure"]["extension_matches_structure"] is False


def test_invalid_zip_is_not_misidentified_as_excel():
    result = analyze_file(bytes([0x50, 0x4b, 0x03, 0x04]) + b"not-a-valid-zip", "archivo.xlsx")
    assert result["file_type"] == "ZIP archive (contenedor no válido)"
    assert result["structure"]["valid_ooxml"] is False



def test_office_zip_expansion_limits_are_enforced():
    from io import BytesIO
    from zipfile import ZIP_STORED, ZipFile

    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("padding.bin", b"A" * (9 * 1024 * 1024))

    result = analyze_file(stream.getvalue(), "large.xlsx")
    assert result["structure"]["inspection"] == "resource_limit"
    assert result["risk"] == "unknown"
    assert result["execution_performed"] is False
    assert result["external_submission"] is False


def test_macro_enabled_word_is_identified_without_execution():
    from io import BytesIO
    from zipfile import ZipFile

    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        archive.writestr("word/vbaProject.bin", b"VBA-project-placeholder")

    result = analyze_file(stream.getvalue(), "report.docm")
    assert result["file_type"] == "Microsoft Word (DOCM)"
    assert result["structure"]["macro_project_present"] is True
    assert result["structure"]["extension_matches_structure"] is True
    assert result["execution_performed"] is False
