import pytest

from unfoldedcircle.device import Device


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://localhost:8080/api/", "http://localhost:8080/api/"),
        ("http://localhost:8080/api", "http://localhost:8080/api/"),
        ("https://myremote/api", "https://myremote/api/"),
    ],
)
def test_validate_url(url, expected):
    assert Device.validate_url(url) == expected


@pytest.mark.parametrize("url", ["foobar://test/api/", "nourl", ""])
def test_validate_url_error(url):
    with pytest.raises(ValueError):
        Device.validate_url(url)
