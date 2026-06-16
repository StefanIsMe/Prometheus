"""Evidence hygiene — capture, redact, rotate.

Ported from CBH ``evidence-hygiene`` skill. Exposes:

- :data:`EVIDENCE_HYGIENE_GUIDE` — the 5-step capture order, ranked
  redaction methods, and post-submission credential rotation.
- :func:`scan_text_for_secrets` — substring scan for cookie / token
  names that may be leaking in screenshots or terminal output.
- :func:`render_evidence_hygiene` — the markdown body of the
  ``/evidence`` slash command.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable

logger = logging.getLogger(__name__)


# Canonical names of secrets that must never appear in a screenshot,
# URL bar, terminal capture, or curl output.
_SENSITIVE_NAMES: tuple[str, ...] = (
    "session",
    "sessionid",
    "session_id",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "auth",
    "authorization",
    "bearer",
    "access_token",
    "id_token",
    "refresh_token",
    "api_key",
    "apikey",
    "x-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "aws_access_key_id",
    "aws_secret_access_key",
    "secret",
    "client_secret",
    "private_key",
    "password",
    "passwd",
    "pwd",
    "ssn",
    "credit_card",
    "pan",
    "csrf",
    "xsrf",
    "csrf_token",
    "xsrf-token",
    "cf_clearance",
    "__cf_bm",
    "cf_bm",
    "_csrf",
    "oauth_token",
    "oauth_verifier",
    "code",
    "state",
    "nextauth",
    "next-auth.session-token",
    "connect.sid",
    "sid",
)


@dataclass(frozen=True)
class EvidenceFinding:
    kind: str
    location: str
    snippet: str
    line: int = 0


_NAME_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(rf"(?i)({re.escape(name)})\s*[=:]\s*([^\s'\"&;]+)") for name in _SENSITIVE_NAMES
)


def scan_text_for_secrets(text: str, *, location: str = "inline") -> list[EvidenceFinding]:
    """Find cookie / token / credential names with values in text.

    Returns one :class:`EvidenceFinding` per match. The list is
    intentionally simple — the goal is a fast post-capture check,
    not a full secret scanner.
    """
    if not text:
        return []
    out: list[EvidenceFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pat in _NAME_PATTERNS:
            for m in pat.finditer(line):
                value = m.group(2)
                if len(value) > 64:
                    value = value[:64] + "…"
                out.append(
                    EvidenceFinding(
                        kind="sensitive_name_value",
                        location=f"{location}:{line_no}",
                        snippet=f"{m.group(1)}={value}",
                        line=line_no,
                    )
                )
    return out


# ----------------------------------------------------------------------
# 5-step capture order (the canonical skill body)
# ----------------------------------------------------------------------
EVIDENCE_HYGIENE_GUIDE = """\
# Evidence Hygiene

## 1. Capture order (always do these in this order)
1. **Redact the source first.** Edit a copy of the screenshot /
   log / terminal output. Replace secret values with `<redacted>`
   *before* the screenshot is taken when possible.
2. **Crop to the relevant frame.** Strip the browser chrome, the OS
   menubar, and any unrelated tabs / terminals.
3. **Strip metadata.** `exiftool -all= file.png` (or your editor's
   "Save for Web" preset).
4. **Verify the screenshot.** Re-open the redacted image and
   confirm no cookie name + value is visible.
5. **Rotate any credentials that appeared in the capture.** Even
   a redacted screenshot is "the credential was exposed in the
   workflow" — rotate it.

## 2. Ranked redaction methods (best → worst)
1. **Re-derive the value.** Re-run the request with a fresh
   throwaway account so the original credential never enters the
   capture pipeline.
2. **Strip from the source.** Edit the HTML / log / terminal
   before the screenshot.
3. **Black bar in the editor.** Draw a solid black box in
   GIMP / Preview / Photoshop; do not rely on a "highlighter" tool
   that may be reversible.
4. **Crop.** When in doubt, crop the secret out of the frame.
5. **NEVER** rely on the in-app "hide" toggle, blurring, or
   emoji substitution — these are reversible.

## 3. Post-submission credential rotation
- **Always** rotate any credential that appeared in *any* stage
  of the PoC — the victim account, the API key, the OAuth
  client secret, the session cookie secret.
- Document the rotation in the report's "Reproduction impact"
  section.

## 4. Common leaks to grep for
`session=`, `sessionid=`, `phpsessid=`, `jsessionid=`,
`__session=`, `_csrf=`, `csrf_token=`, `xsrf-token=`,
`bearer `, `Authorization:`, `access_token=`, `id_token=`,
`refresh_token=`, `api_key=`, `x-api-key=`, `aws_access_key_id=`,
`password=`, `client_secret=`, `private_key=`, `code=`, `state=`,
`nextauth.session-token=`, `connect.sid=`, `cf_clearance=`.

Use `/evidence` to print this guide.

"""


def render_evidence_hygiene() -> str:
    """Return the markdown body of the ``/evidence`` slash command."""
    return EVIDENCE_HYGIENE_GUIDE


# ----------------------------------------------------------------------
# Image / file post-check (best-effort)
# ----------------------------------------------------------------------
def scan_image_for_secrets(path: str) -> list[EvidenceFinding]:
    """Best-effort scan of an image file's metadata + OCR-extracted text.

    Uses exiftool (if available) and tesseract (if available) to look
    for sensitive name + value patterns. Returns an empty list when
    no tool is present — the caller should not assume a finding.
    """
    import shutil
    import subprocess
    from pathlib import Path

    p = Path(path)
    if not p.is_file():
        return []
    findings: list[EvidenceFinding] = []
    if shutil.which("exiftool"):
        try:
            r = subprocess.run(
                [
                    "exiftool",
                    "-Comment",
                    "-Description",
                    "-UserComment",
                    "-ImageDescription",
                    "-XPComment",
                    str(p),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for hit in scan_text_for_secrets(r.stdout, location=f"exiftool:{p.name}"):
                findings.append(hit)
        except Exception:
            logger.debug("exiftool scan failed for %s, ignoring", p, exc_info=True)
    if shutil.which("tesseract"):
        try:
            r = subprocess.run(
                ["tesseract", str(p), "-", "-l", "eng"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for hit in scan_text_for_secrets(r.stdout, location=f"ocr:{p.name}"):
                findings.append(hit)
        except Exception:
            logger.debug("tesseract OCR failed for %s, ignoring", p, exc_info=True)
    return findings


__all__ = [
    "EVIDENCE_HYGIENE_GUIDE",
    "EvidenceFinding",
    "render_evidence_hygiene",
    "scan_image_for_secrets",
    "scan_text_for_secrets",
]
