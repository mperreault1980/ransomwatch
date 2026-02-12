"""Tests for the defang module."""

from ransomwatch.defang import extract_ips_from_text, refang_ip


class TestRefangIP:
    def test_bracket_dot(self):
        assert refang_ip("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_bracket_word_dot(self):
        assert refang_ip("192[dot]168[dot]1[dot]1") == "192.168.1.1"

    def test_paren_dot(self):
        assert refang_ip("192(.)168(.)1(.)1") == "192.168.1.1"

    def test_paren_word_dot(self):
        assert refang_ip("192(dot)168(dot)1(dot)1") == "192.168.1.1"

    def test_normal_ip_unchanged(self):
        assert refang_ip("10.0.0.1") == "10.0.0.1"

    def test_mixed_notation(self):
        assert refang_ip("10[.]0(.)1[dot]2") == "10.0.1.2"

    def test_empty_string(self):
        assert refang_ip("") == ""

    def test_case_insensitive(self):
        assert refang_ip("10[DOT]0[Dot]1[dot]2") == "10.0.1.2"


class TestExtractIPsFromText:
    def test_single_ip(self):
        assert extract_ips_from_text("The IP is 1.2.3.4 in the text") == ["1.2.3.4"]

    def test_defanged_ip(self):
        assert extract_ips_from_text("Connect to 10[.]0[.]0[.]1") == ["10.0.0.1"]

    def test_multiple_ips(self):
        text = "Found 1.2.3.4 and 5.6.7.8 in logs"
        result = extract_ips_from_text(text)
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_deduplication(self):
        text = "IP 1.2.3.4 appeared twice: 1.2.3.4"
        result = extract_ips_from_text(text)
        assert result == ["1.2.3.4"]

    def test_no_ips(self):
        assert extract_ips_from_text("No addresses here") == []

    def test_mixed_defanged_and_normal(self):
        text = "Hosts: 10[.]0[.]0[.]1 and 192.168.1.1"
        result = extract_ips_from_text(text)
        assert result == ["10.0.0.1", "192.168.1.1"]

    def test_invalid_octets_excluded(self):
        # 999.999.999.999 should not match
        assert extract_ips_from_text("Not an IP: 999.999.999.999") == []

    def test_boundary_values(self):
        assert extract_ips_from_text("0.0.0.0 and 255.255.255.255") == [
            "0.0.0.0",
            "255.255.255.255",
        ]
