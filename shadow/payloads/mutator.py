"""Payload mutator — standalone mutation and WAF bypass primitives."""

from urllib.parse import quote


class PayloadMutator:
    """Provides mutation primitives for payload WAF bypass."""

    def url_encode(self, payload: str) -> str:
        """URL-encode all characters."""
        return quote(payload, safe="")

    def double_url_encode(self, payload: str) -> str:
        """Double URL-encode all characters."""
        return quote(quote(payload, safe=""), safe="")

    def html_entity_encode(self, payload: str) -> str:
        """HTML entity encode special characters."""
        return (
            payload
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("'", "&#39;")
            .replace('"', "&quot;")
        )

    def comment_inject(self, payload: str) -> str:
        """Replace spaces with SQL comment sequences."""
        return payload.replace(" ", "/**/")

    def case_vary(self, payload: str) -> str:
        """Alternate upper/lower case to bypass case-sensitive filters."""
        result = []
        for i, c in enumerate(payload):
            result.append(c.upper() if i % 2 == 0 else c.lower())
        return "".join(result)

    def whitespace_sub(self, payload: str) -> str:
        """Substitute spaces with tab characters."""
        return payload.replace(" ", "\t")

    def null_byte(self, payload: str) -> str:
        """Append null byte for filter bypass."""
        return payload + "%00"

    def unicode_encode(self, payload: str) -> str:
        """Unicode-encode non-ASCII and special characters."""
        special = set("'\"<>&;=()")
        result = []
        for c in payload:
            if c in special or ord(c) > 127:
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)

    def mutate_all(self, payload: str) -> list[str]:
        """Return all mutations of a payload including the original."""
        mutations = [payload]
        for fn in [
            self.url_encode,
            self.double_url_encode,
            self.html_entity_encode,
            self.comment_inject,
            self.case_vary,
            self.whitespace_sub,
            self.unicode_encode,
        ]:
            try:
                mutated = fn(payload)
                if mutated not in mutations:
                    mutations.append(mutated)
            except Exception:
                continue
        return mutations

    def waf_bypass_variants(self, payload: str, waf_vendor: str = "generic") -> list[str]:
        """Return WAF-vendor-specific bypass variants."""
        vendor = waf_vendor.lower()
        variants = []
        if vendor in ("cloudflare", "generic"):
            variants.append(self.url_encode(payload))
            variants.append(self.double_url_encode(payload))
            variants.append(self.unicode_encode(payload))
        if vendor in ("modsecurity", "generic"):
            variants.append(self.comment_inject(payload))
            variants.append(self.whitespace_sub(payload))
            variants.append(self.case_vary(payload))
        if vendor in ("aws waf", "aws_waf", "generic"):
            variants.append(self.url_encode(payload))
            variants.append(self.html_entity_encode(payload))
        if not variants:
            variants = self.mutate_all(payload)
        return list(dict.fromkeys(variants))  # deduplicate preserving order
