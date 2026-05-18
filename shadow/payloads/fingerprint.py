"""Target fingerprinter — profiles a target before payload generation."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TargetProfile:
    target: str
    framework: str = "unknown"       # Laravel, Django, Spring, Express, etc.
    db_type: str = "unknown"         # MySQL, PostgreSQL, MSSQL, SQLite, etc.
    waf_vendor: str = "none"         # ModSecurity, Cloudflare, AWS WAF, etc.
    filtered_chars: set = field(default_factory=set)  # chars that get stripped/blocked
    error_verbosity: str = "silent"  # verbose / silent
    timing_baseline_ms: float = 0.0  # average response time in ms
    server_header: str = ""
    tech_stack: list = field(default_factory=list)


class TargetFingerprinter:
    # Framework detection signatures
    FRAMEWORK_SIGNATURES = {
        "Laravel": ["laravel_session", "X-Powered-By: PHP", "XSRF-TOKEN"],
        "Django": ["csrftoken", "X-Frame-Options: SAMEORIGIN", "django"],
        "Spring": ["JSESSIONID", "X-Application-Context", "spring"],
        "Express": ["X-Powered-By: Express", "connect.sid"],
        "Rails": ["_session_id", "X-Powered-By: Phusion Passenger", "rails"],
        "ASP.NET": ["ASP.NET_SessionId", "X-Powered-By: ASP.NET", "__RequestVerificationToken"],
    }

    # DB detection from error messages
    DB_ERROR_SIGNATURES = {
        "MySQL": ["you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows"],
        "PostgreSQL": ["pg_query", "pg_exec", "postgresql", "syntax error at or near"],
        "MSSQL": ["microsoft sql server", "unclosed quotation mark", "incorrect syntax near"],
        "SQLite": ["sqlite_", "sqlite3.", "no such table"],
        "Oracle": ["ora-", "oracle error", "quoted string not properly terminated"],
    }

    # WAF detection signatures
    WAF_SIGNATURES = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
        "ModSecurity": ["mod_security", "modsecurity", "not acceptable"],
        "AWS WAF": ["x-amzn-requestid", "aws-waf"],
        "Akamai": ["akamai", "x-akamai-transformed"],
        "Sucuri": ["sucuri", "x-sucuri-id"],
    }

    def profile(self, target: str, response_headers: dict = None,
                response_body: str = "", error_messages: list = None,
                timing_samples: list = None) -> TargetProfile:
        """Build a TargetProfile from response data."""
        profile = TargetProfile(target=target)

        headers = response_headers or {}
        errors = error_messages or []
        timings = timing_samples or []

        profile.framework = self._detect_framework(headers, response_body)
        profile.db_type = self._detect_db(errors, response_body)
        profile.waf_vendor = self._detect_waf(headers, response_body)
        profile.error_verbosity = "verbose" if errors else "silent"
        profile.server_header = headers.get("Server", headers.get("server", ""))
        profile.timing_baseline_ms = (
            sum(timings) / len(timings) if timings else 0.0
        )

        # Build tech stack list
        stack = []
        if profile.framework != "unknown":
            stack.append(profile.framework)
        if profile.db_type != "unknown":
            stack.append(profile.db_type)
        if profile.waf_vendor != "none":
            stack.append(f"WAF:{profile.waf_vendor}")
        profile.tech_stack = stack

        return profile

    def _detect_framework(self, headers: dict, body: str) -> str:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        # Build both individual values and "key: value" combined strings for matching
        header_strings = list(headers_lower.values()) + [
            f"{k}: {v}" for k, v in headers_lower.items()
        ]
        body_lower = body.lower()
        for framework, sigs in self.FRAMEWORK_SIGNATURES.items():
            for sig in sigs:
                sig_lower = sig.lower()
                if any(sig_lower in s for s in header_strings):
                    return framework
                if sig_lower in body_lower:
                    return framework
        return "unknown"

    def _detect_db(self, errors: list, body: str) -> str:
        combined = " ".join(errors).lower() + " " + body.lower()
        for db, sigs in self.DB_ERROR_SIGNATURES.items():
            if any(sig in combined for sig in sigs):
                return db
        return "unknown"

    def _detect_waf(self, headers: dict, body: str) -> str:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        for waf, sigs in self.WAF_SIGNATURES.items():
            for sig in sigs:
                sig_lower = sig.lower()
                if any(sig_lower in k or sig_lower in v for k, v in headers_lower.items()):
                    return waf
                if sig_lower in body_lower:
                    return waf
        return "none"
