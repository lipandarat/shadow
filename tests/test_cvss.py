import pytest
from shadow.core.models import Finding, Severity
from shadow.core.cvss import CVSSCalculator, CVSSVector


class TestCVSSVector:
    def test_vector_string_format(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        s = str(v)
        assert s.startswith("CVSS:3.1/")
        assert "AV:N" in s
        assert "C:H" in s

    def test_zero_impact_returns_zero(self):
        v = CVSSVector(C="N", I="N", A="N")
        assert v.calculate() == 0.0

    def test_high_impact_network_score(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        score = v.calculate()
        assert score >= 9.0  # Critical

    def test_low_impact_score(self):
        v = CVSSVector(AV="N", AC="H", PR="H", UI="R", S="U", C="L", I="N", A="N")
        score = v.calculate()
        assert score < 5.0


class TestCVSSCalculator:
    def test_sqli_is_high_or_critical(self):
        f = Finding(title="SQLi", vuln_class="sqli", target="https://x.com")
        score, vector = CVSSCalculator.calculate(f)
        assert score >= 7.0
        assert "CVSS:3.1" in vector

    def test_xss_is_medium(self):
        f = Finding(title="XSS", vuln_class="xss", target="https://x.com")
        score, vector = CVSSCalculator.calculate(f)
        assert 3.0 <= score <= 7.0

    def test_lfi_has_high_confidentiality(self):
        f = Finding(title="LFI", vuln_class="lfi", target="https://x.com")
        score, vector = CVSSCalculator.calculate(f)
        assert "C:H" in vector

    def test_rce_is_critical(self):
        f = Finding(title="RCE", vuln_class="rce", target="https://x.com")
        score, vector = CVSSCalculator.calculate(f)
        assert score >= 9.0

    def test_severity_from_score_critical(self):
        assert CVSSCalculator.severity_from_score(9.5) == Severity.CRITICAL

    def test_severity_from_score_high(self):
        assert CVSSCalculator.severity_from_score(7.5) == Severity.HIGH

    def test_severity_from_score_medium(self):
        assert CVSSCalculator.severity_from_score(5.0) == Severity.MEDIUM

    def test_severity_from_score_low(self):
        assert CVSSCalculator.severity_from_score(2.0) == Severity.LOW

    def test_severity_from_score_info(self):
        assert CVSSCalculator.severity_from_score(0.0) == Severity.INFO
