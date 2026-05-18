"""CVSS 3.1 auto-calibration — prevents severity inflation."""

import math
from dataclasses import dataclass
from shadow.core.models import Finding, Severity


@dataclass
class CVSSVector:
    AV: str = "N"   # Attack Vector: N/A/L/P
    AC: str = "L"   # Attack Complexity: L/H
    PR: str = "N"   # Privileges Required: N/L/H
    UI: str = "N"   # User Interaction: N/R
    S: str = "U"    # Scope: U/C
    C: str = "N"    # Confidentiality: N/L/H
    I: str = "N"    # Integrity: N/L/H
    A: str = "N"    # Availability: N/L/H

    def calculate(self) -> float:
        """Calculate CVSS 3.1 base score."""
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_map = {"N": 0.85, "R": 0.62}
        cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}

        av = av_map.get(self.AV, 0.85)
        ac = ac_map.get(self.AC, 0.77)
        pr = (pr_map_c if self.S == "C" else pr_map_u).get(self.PR, 0.85)
        ui = ui_map.get(self.UI, 0.85)
        c = cia_map.get(self.C, 0.0)
        i = cia_map.get(self.I, 0.0)
        a = cia_map.get(self.A, 0.0)

        iss = 1 - (1 - c) * (1 - i) * (1 - a)

        if self.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if self.S == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal
        return math.ceil(score * 10) / 10

    def __str__(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )


class CVSSCalculator:
    @staticmethod
    def calculate(finding: Finding) -> tuple[float, str]:
        """Derive CVSS 3.1 score from finding metadata."""
        vector = CVSSCalculator._derive_vector(finding)
        score = vector.calculate()
        return score, str(vector)

    @staticmethod
    def severity_from_score(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _derive_vector(finding: Finding) -> CVSSVector:
        vuln = finding.vuln_class.lower()
        v = CVSSVector()

        # Attack Vector
        v.AV = "N"  # default network

        # Attack Complexity
        v.AC = "L"  # default low

        # Privileges Required
        if any(x in vuln for x in ["idor", "auth", "priv"]):
            v.PR = "L"
        else:
            v.PR = "N"

        # User Interaction
        if any(x in vuln for x in ["xss", "csrf", "clickjack", "phish"]):
            v.UI = "R"
        else:
            v.UI = "N"

        # Scope
        v.S = "U"

        # CIA Impact based on vuln class
        if any(x in vuln for x in ["sqli", "rce", "cmdi", "xxe", "ssti"]):
            v.C = "H"
            v.I = "H"
            v.A = "H"
        elif any(x in vuln for x in ["xss", "csrf", "ssrf"]):
            v.C = "L"
            v.I = "L"
            v.A = "N"
        elif any(x in vuln for x in ["lfi", "path", "traversal"]):
            v.C = "H"
            v.I = "N"
            v.A = "N"
        elif any(x in vuln for x in ["idor", "bola", "auth"]):
            v.C = "H"
            v.I = "L"
            v.A = "N"
        else:
            v.C = "L"
            v.I = "N"
            v.A = "N"

        return v
