import pytest

from src.services.url_inspection_service import URLInspectionService


@pytest.mark.ssrf
def test_is_safe_ip_public_ipv4():
    assert URLInspectionService.is_safe_ip(
        "8.8.8.8"
    ) is True


@pytest.mark.ssrf
def test_is_safe_ip_loopback():
    assert URLInspectionService.is_safe_ip(
        "127.0.0.1"
    ) is False


@pytest.mark.ssrf
def test_is_safe_ip_private():
    assert URLInspectionService.is_safe_ip(
        "192.168.1.10"
    ) is False


@pytest.mark.ssrf
def test_is_safe_ip_link_local():
    assert URLInspectionService.is_safe_ip(
        "169.254.169.254"
    ) is False


@pytest.mark.ssrf
def test_is_safe_ip_unspecified():
    assert URLInspectionService.is_safe_ip(
        "0.0.0.0"
    ) is False


@pytest.mark.ssrf
def test_is_safe_hostname_loopback():
    assert URLInspectionService.is_safe_hostname(
        "localhost"
    ) is False


@pytest.mark.ssrf
def test_timeout_compatibility():
    service = URLInspectionService()

    assert service.timeout >= 1

    service.timeout = 10

    assert service.timeout == 10