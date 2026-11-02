from io import BytesIO

import pytest
from openpyxl import Workbook
from fastapi import HTTPException

from kyros.web import _read_ioc_rows


def make_xlsx(rows):
    workbook = Workbook()
    sheet = workbook.active
    for row in rows:
        sheet.append(row)
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def test_reads_xlsx_ioc_rows():
    raw = make_xlsx([
        ["indicator_type", "indicator", "confidence", "source", "description"],
        ["ip", "8.8.8.8", 90, "internal", "test IOC"],
    ])
    rows, file_type = _read_ioc_rows("indicators.xlsx", raw)
    assert file_type == "xlsx"
    assert rows[0]["indicator"] == "8.8.8.8"
    assert rows[0]["confidence"] == "90"


def test_rejects_xlsx_without_required_columns():
    raw = make_xlsx([["type", "value"], ["ip", "8.8.8.8"]])
    with pytest.raises(HTTPException) as exc:
        _read_ioc_rows("indicators.xlsx", raw)
    assert exc.value.status_code == 422


def test_rejects_legacy_xls():
    with pytest.raises(HTTPException) as exc:
        _read_ioc_rows("indicators.xls", b"not an xls")
    assert exc.value.status_code == 415


def test_reads_utf8_csv():
    rows, file_type = _read_ioc_rows(
        "indicators.csv",
        b"indicator_type,indicator,confidence\nip,8.8.8.8,90\n",
    )
    assert file_type == "csv"
    assert rows[0]["indicator"] == "8.8.8.8"
