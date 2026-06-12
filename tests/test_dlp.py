"""Tests for R6 (DLP detection engine) scenarios.

The engine is tested pure: scan() in, Detection spans out. No pipeline here —
direction-aware actions (R7) are covered in test_pipeline.py.
"""

import pytest

from tollbooth.dlp import Detection, luhn_check, scan
from tollbooth.policy import Decision

# Industry-standard test card numbers (Luhn-valid, never real accounts).
VISA = "4111111111111111"
VISA_BAD_LUHN = "4111111111111112"
AMEX = "378282246310005"
MASTERCARD = "5555555555554444"
DISCOVER = "6011111111111117"

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def ids(detections: list[Detection]) -> list[str]:
    return [d.pattern_id for d in detections]


class TestLuhn:
    def test_valid_card_passes(self):
        assert luhn_check(VISA)
        assert luhn_check(AMEX)

    def test_invalid_checksum_fails(self):
        assert not luhn_check(VISA_BAD_LUHN)

    def test_separators_are_ignored(self):
        assert luhn_check("4111-1111-1111-1111")

    def test_length_bounds(self):
        assert not luhn_check("411111111111")  # 12 digits: too short
        assert not luhn_check("4" * 20)  # too long


class TestPanScenarios:
    # R6 scenario: PAN detected with Luhn validation
    def test_luhn_valid_pan_detected(self):
        assert ids(scan(f"card: {VISA}")) == ["pan"]

    # R6 scenario: Luhn-invalid number is not flagged
    def test_luhn_invalid_pan_not_flagged(self):
        assert scan(f"card: {VISA_BAD_LUHN}") == []

    @pytest.mark.parametrize("pan", [VISA, AMEX, MASTERCARD, DISCOVER])
    def test_all_brands_detected(self, pan):
        assert ids(scan(f"number {pan} on file")) == ["pan"]

    def test_span_covers_separated_pan(self):
        text = "card 4111 1111 1111 1111 expires 11/29"
        (d,) = scan(text)
        assert text[d.start : d.end] == "4111 1111 1111 1111"


class TestOverlapSuppression:
    # R6 scenario: overlapping patterns resolve to most specific.
    # The value matches BOTH api-key-assignment (generic) and aws-access-key
    # (specific); only the specific detection may be reported.
    def test_specific_pattern_suppresses_generic(self):
        assert ids(scan(f"api_key={AWS_KEY}")) == ["aws-access-key"]

    def test_non_overlapping_detections_both_reported(self):
        text = f"key {AWS_KEY} and ssn 123-45-6789"
        assert ids(scan(text)) == ["aws-access-key", "ssn"]


class TestPatternLibrary:
    @pytest.mark.parametrize(
        ("pattern_id", "text", "expected_value"),
        [
            ("aws-access-key", f"export KEY={AWS_KEY} # creds", AWS_KEY),
            (
                "aws-secret-key",
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
            (
                "github-token",
                "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 ok",
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            ),
            (
                "connection-string",
                "url postgres://admin:hunter22@db.internal:5432/prod end",
                "postgres://admin:hunter22@db.internal:5432/prod",
            ),
            ("ssn", "applicant ssn 123-45-6789 verified", "123-45-6789"),
            ("us-phone", "call (415) 555-2671 today", "(415) 555-2671"),
            ("us-phone", "fax: 415-555-2671", "415-555-2671"),
            (
                "api-key-assignment",
                "api_key=sk_live_abcdef123456789012345",
                "api_key=sk_live_abcdef123456789012345",
            ),
            (
                "password-assignment",
                'password: "correct-horse-battery1"',
                'password: "correct-horse-battery1',
            ),
        ],
    )
    def test_pattern_detects_with_exact_span(self, pattern_id, text, expected_value):
        (d,) = scan(text)
        assert d.pattern_id == pattern_id
        assert text[d.start : d.end] == expected_value

    def test_pem_header_alone_detected(self):
        assert ids(scan("-----BEGIN OPENSSH PRIVATE KEY-----")) == ["private-key-pem"]

    # Section-review findings, pinned so the regexes don't regress:
    @pytest.mark.regression
    def test_review_findings_detected(self):
        # 2-series Mastercard BIN (issued since 2017), Luhn-valid
        assert ids(scan("card 2221000000000009")) == ["pan"]
        # Encrypted PKCS#8 key (standard openssl output)
        assert ids(scan("-----BEGIN ENCRYPTED PRIVATE KEY-----")) == ["private-key-pem"]
        # Redis URL with empty username — still a live credential
        assert ids(scan("redis://:s3cretpass@cache.internal:6379/0")) == ["connection-string"]
        # pwd=value is a credential assignment (pwd: is shell noise, below)
        assert ids(scan("pwd=hunter22secret")) == ["password-assignment"]

    @pytest.mark.regression
    def test_detection_repr_never_carries_value(self):
        # Tripwire: a future refactor adding a value field to Detection would
        # silently violate "detected values never appear in logs" (R6, S1).
        text = f"key {AWS_KEY} and card {VISA}"
        assert AWS_KEY not in repr(scan(text))
        assert VISA not in repr(scan(text))

    def test_full_pem_block_span_covers_key_material(self):
        # The span must swallow the body: redacting only the header would
        # pass the actual key material through (R7).
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA5Fak3+sentinel/keymaterial+lines\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"dumped:\n{block}\ndone"
        (d,) = scan(text)
        assert d.pattern_id == "private-key-pem"
        assert text[d.start : d.end] == block


class TestFalsePositiveCorpus:
    # Cross-cutting Pattern 2: legitimate data superficially resembling
    # sensitive data must NOT be flagged.
    @pytest.mark.parametrize(
        "text",
        [
            "deployed commit a3f5c2e8b9d0147263544f5061728394a5b6c7d8 to prod",
            "request id 550e8400-e29b-41d4-a716-446655440000",
            "finished at 2026-06-12T14:30:00Z",
            "upgraded to version 1.2.30 yesterday",
            "order number 9876543210987654 shipped",
            f"checksum mismatch: {VISA_BAD_LUHN}",  # 16 digits, Luhn-invalid
            "password: ********",  # masked, not a real credential
            "api_key=your_integration_key_here",  # placeholder
            "db at postgres://localhost:5432/app",  # no credentials in URL
            "listening on 192.168.100.200:8080",
            "meeting 2026-06-12 from 10:30-12:45",
            "pwd: /var/lib/jenkins/workspace",  # shell working directory, not a password
            "pwd: ignoring non-option arguments",  # command output prefixed by its name

        ],
    )
    def test_benign_content_not_flagged(self, text):
        assert scan(text) == []


class TestDlpRequestInterceptor:
    def check(self, args, overrides=None):
        from tollbooth.dlp import DlpRequestInterceptor
        from tollbooth.pipeline import ToolCall

        interceptor = DlpRequestInterceptor(overrides=overrides)
        return interceptor.check_request(ToolCall(server="crm", tool="update", args=args))

    # R7 scenario: request with secret is blocked — pattern named, value never echoed
    def test_pan_in_args_blocked_without_echoing_value(self):
        result = self.check({"card": VISA})
        assert result.decision is Decision.DENY
        assert "pan" in result.message
        assert VISA not in result.message
        assert VISA not in (result.rule_name or "")

    def test_nested_args_are_scanned(self):
        result = self.check({"meta": {"notes": [f"aws key {AWS_KEY}"]}})
        assert result.decision is Decision.DENY
        assert "aws-access-key" in result.message

    def test_numeric_leaf_is_scanned(self):
        # A PAN arriving as a JSON number must not slip past the walk.
        result = self.check({"card_number": int(VISA)})
        assert result.decision is Decision.DENY

    def test_clean_args_allowed(self):
        result = self.check({"path": "/tmp/notes.txt", "limit": 10})
        assert result.decision is Decision.ALLOW

    def test_per_pattern_allow_override(self):
        result = self.check({"card": VISA}, overrides={"pan": "allow"})
        assert result.decision is Decision.ALLOW


class TestDlpResultInterceptor:
    def check(self, content, overrides=None):
        from tollbooth.dlp import DlpResultInterceptor
        from tollbooth.pipeline import ToolCall

        interceptor = DlpResultInterceptor(overrides=overrides)
        return interceptor.check_result(
            ToolCall(server="fs", tool="read_file", args={}), content
        )

    # R7 scenario: result with secret is redacted, rest of the result intact
    def test_secret_redacted_in_place(self):
        edit = self.check(f"export AWS_KEY={AWS_KEY} # deploy creds")
        assert edit.content == "export AWS_KEY=[REDACTED:aws-access-key] # deploy creds"
        assert edit.reason_ids == ("aws-access-key",)

    def test_multiple_detections_all_redacted(self):
        edit = self.check(f"key {AWS_KEY}, ssn 123-45-6789, card {VISA}.")
        assert edit.content == (
            "key [REDACTED:aws-access-key], ssn [REDACTED:ssn], card [REDACTED:pan]."
        )
        assert edit.reason_ids == ("aws-access-key", "pan", "ssn")

    def test_clean_content_untouched(self):
        edit = self.check("nothing sensitive here")
        assert edit.content == "nothing sensitive here"
        assert edit.reason_ids == ()

    # R7 scenario: per-pattern override — block instead of redact
    def test_block_override_raises_block_result(self):
        from tollbooth.pipeline import BlockResult

        with pytest.raises(BlockResult) as exc_info:
            self.check(
                "-----BEGIN PRIVATE KEY-----\nhush\n-----END PRIVATE KEY-----",
                overrides={"private-key-pem": "block"},
            )
        assert exc_info.value.reason_id == "private-key-pem"

    def test_allow_override_leaves_content(self):
        text = "applicant ssn 123-45-6789"
        edit = self.check(text, overrides={"ssn": "allow"})
        assert edit.content == text
        assert edit.reason_ids == ()


class TestUnicodeOffsets:
    # Cross-cutting Pattern 7: non-ASCII content before/around a secret must
    # not skew spans — redaction (R7) slices by these offsets.
    def test_span_exact_after_composed_unicode(self):
        text = f"café señor {AWS_KEY} — fin"
        (d,) = scan(text)
        assert text[d.start : d.end] == AWS_KEY

    def test_span_exact_after_decomposed_unicode(self):
        text = f"café {AWS_KEY}"
        (d,) = scan(text)
        assert text[d.start : d.end] == AWS_KEY
