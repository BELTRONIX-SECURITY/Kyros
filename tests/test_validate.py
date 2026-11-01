import pytest

from kyros.validate import split_email


def test_correo_valido():
    assert split_email("Ana.Perez+x@Example.COM") == ("Ana.Perez+x", "example.com")


@pytest.mark.parametrize("bad", ["", "sin-arroba", "a@b", "a@@b.com", "a b@c.com", "a@-b.com"])
def test_correo_invalido(bad):
    with pytest.raises(ValueError):
        split_email(bad)
