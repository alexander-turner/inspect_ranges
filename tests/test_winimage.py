"""Windows installer template pins (phase review round 1, finding A3): the install-time answer file is the second place the admin password interpolates into XML, and an unescaped regression there burns the whole 40-minute install timeout instead of failing a parse."""

from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from inspect_ranges._runtime.winimage import (
    _INSTALL_UNATTEND,  # pyright: ignore[reportPrivateUsage]
)


def test_install_unattend_parses_with_a_hostile_password(tmp_path: Path) -> None:
    """Every interpolation point in the installer template survives an XML-hostile password; the rendered document parses and carries the escaped value at both password sites (AdministratorPassword + AutoLogon)."""
    hostile = """<&>"'pass</Value>"""
    rendered = _INSTALL_UNATTEND.replace("__ADMIN_PASSWORD__", escape(hostile))
    root = ElementTree.fromstring(rendered)
    ns = "{urn:schemas-microsoft-com:unattend}"
    values = [
        element.text
        for element in root.iter(f"{ns}Value")
        if element.text and "pass" in element.text
    ]
    assert len(values) >= 2, "both password sites must carry the value"
    assert all(v == hostile for v in values), "escaping must round-trip exactly"
    # the only template placeholder is the password: nothing else is caller data
    assert "__ADMIN_PASSWORD__" not in rendered
