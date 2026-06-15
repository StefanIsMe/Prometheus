"""Curated XBOW pilot — 5 challenges, all L2, build in < 60s each.

Why this set (per the plan):

* XBEN-001-24 / 002-24 / 003-24 — three IDOR variants (int id,
  UUID id, custom-header id). Exercises the same skill three ways.
* XBEN-050-24 — stored/reflected XSS. Different vuln class so we
  can see whether skills fail across the boundary, not just within
  one class.
* XBEN-100-24 — hidden admin endpoint. The "exposed unauthenticated"
  class that maps to the recon/threat_feeds skill.

All five are L2, all reachable in < 2 min, all use a buildable
docker-compose, and all exercise a skill prometheus already loads.
The harness can be extended to the full 104-challenge corpus by
just adding more ``XBOWChallenge`` rows; the runner picks them up
by id from ``--ids``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class XBOWChallenge:
    """A single XBOW challenge descriptor.

    Mirrors :class:`prometheus.eval.EvalChallenge` so the two
    harnesses can be cross-fed (an XBOW challenge can be wrapped as
    an eval challenge for the skills-on/off ablation if anyone ever
    wants to).
    """

    id: str
    level: int
    tags: tuple[str, ...]
    build_target: str
    host_port: int
    description: str
    timeout_s: int = 900
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "level": self.level,
            "tags": list(self.tags),
            "build_target": self.build_target,
            "host_port": self.host_port,
            "description": self.description,
            "timeout_s": self.timeout_s,
        }


# The full 104-challenge corpus. ``host_port`` is the host-side
# port we bind on 127.0.0.1 when the challenge is up; prometheus
# is launched with ``--target http://127.0.0.1:<host_port>``. Ports
# are allocated 18000..18103 in id order so the runner can address
# any challenge by id without port collision (even when four
# challenges are in flight at the same time under --concurrency 4).
# The level + tags below are pulled from each challenge's
# benchmark.json in the upstream repo.
PILOT: list[XBOWChallenge] = [
    XBOWChallenge(
        id='XBEN-001-24',
        level=2,
        tags=('idor', 'default_credentials'),
        build_target='benchmarks/XBEN-001-24',
        host_port=18000,
        description='XBEN-001-24',
    ),
    XBOWChallenge(
        id='XBEN-002-24',
        level=2,
        tags=('idor', 'default_credentials'),
        build_target='benchmarks/XBEN-002-24',
        host_port=18001,
        description='XBEN-002-24',
    ),
    XBOWChallenge(
        id='XBEN-003-24',
        level=2,
        tags=('idor', 'default_credentials'),
        build_target='benchmarks/XBEN-003-24',
        host_port=18002,
        description='XBEN-003-24',
    ),
    XBOWChallenge(
        id='XBEN-004-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-004-24',
        host_port=18003,
        description='XBEN-004-24',
    ),
    XBOWChallenge(
        id='XBEN-005-24',
        level=1,
        tags=('idor', 'jwt', 'default_credentials'),
        build_target='benchmarks/XBEN-005-24',
        host_port=18004,
        description='XBEN-005-24',
    ),
    XBOWChallenge(
        id='XBEN-006-24',
        level=1,
        tags=('idor', 'sqli'),
        build_target='benchmarks/XBEN-006-24',
        host_port=18005,
        description='XBEN-006-24',
    ),
    XBOWChallenge(
        id='XBEN-007-24',
        level=2,
        tags=('brute_force', 'graphql', 'idor'),
        build_target='benchmarks/XBEN-007-24',
        host_port=18006,
        description='XBEN-007-24',
    ),
    XBOWChallenge(
        id='XBEN-008-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-008-24',
        host_port=18007,
        description='XBEN-008-24',
    ),
    XBOWChallenge(
        id='XBEN-009-24',
        level=1,
        tags=('ssti',),
        build_target='benchmarks/XBEN-009-24',
        host_port=18008,
        description='XBEN-009-24',
    ),
    XBOWChallenge(
        id='XBEN-010-24',
        level=3,
        tags=('xss',),
        build_target='benchmarks/XBEN-010-24',
        host_port=18009,
        description='XBEN-010-24',
    ),
    XBOWChallenge(
        id='XBEN-011-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-011-24',
        host_port=18010,
        description='XBEN-011-24',
    ),
    XBOWChallenge(
        id='XBEN-012-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-012-24',
        host_port=18011,
        description='XBEN-012-24',
    ),
    XBOWChallenge(
        id='XBEN-013-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-013-24',
        host_port=18012,
        description='XBEN-013-24',
    ),
    XBOWChallenge(
        id='XBEN-014-24',
        level=2,
        tags=('privilege_escalation', 'insecure_deserialization'),
        build_target='benchmarks/XBEN-014-24',
        host_port=18013,
        description='XBEN-014-24',
    ),
    XBOWChallenge(
        id='XBEN-015-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-015-24',
        host_port=18014,
        description='XBEN-015-24',
    ),
    XBOWChallenge(
        id='XBEN-016-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-016-24',
        host_port=18015,
        description='XBEN-016-24',
    ),
    XBOWChallenge(
        id='XBEN-017-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-017-24',
        host_port=18016,
        description='XBEN-017-24',
    ),
    XBOWChallenge(
        id='XBEN-018-24',
        level=3,
        tags=('xss',),
        build_target='benchmarks/XBEN-018-24',
        host_port=18017,
        description='XBEN-018-24',
    ),
    XBOWChallenge(
        id='XBEN-019-24',
        level=1,
        tags=('lfi', 'information_disclosure'),
        build_target='benchmarks/XBEN-019-24',
        host_port=18018,
        description='XBEN-019-24',
    ),
    XBOWChallenge(
        id='XBEN-020-24',
        level=1,
        tags=('ssrf',),
        build_target='benchmarks/XBEN-020-24',
        host_port=18019,
        description='XBEN-020-24',
    ),
    XBOWChallenge(
        id='XBEN-021-24',
        level=1,
        tags=('idor', 'default_credentials'),
        build_target='benchmarks/XBEN-021-24',
        host_port=18020,
        description='XBEN-021-24',
    ),
    XBOWChallenge(
        id='XBEN-022-24',
        level=2,
        tags=('ssti', 'default_credentials', 'path_traversal'),
        build_target='benchmarks/XBEN-022-24',
        host_port=18021,
        description='XBEN-022-24',
    ),
    XBOWChallenge(
        id='XBEN-023-24',
        level=2,
        tags=('ssti', 'default_credentials'),
        build_target='benchmarks/XBEN-023-24',
        host_port=18022,
        description='XBEN-023-24',
    ),
    XBOWChallenge(
        id='XBEN-024-24',
        level=1,
        tags=('ssrf',),
        build_target='benchmarks/XBEN-024-24',
        host_port=18023,
        description='XBEN-024-24',
    ),
    XBOWChallenge(
        id='XBEN-025-24',
        level=2,
        tags=('ssti', 'default_credentials'),
        build_target='benchmarks/XBEN-025-24',
        host_port=18024,
        description='XBEN-025-24',
    ),
    XBOWChallenge(
        id='XBEN-026-24',
        level=1,
        tags=('cve', 'path_traversal', 'lfi'),
        build_target='benchmarks/XBEN-026-24',
        host_port=18025,
        description='XBEN-026-24',
    ),
    XBOWChallenge(
        id='XBEN-027-24',
        level=2,
        tags=('idor', 'idor', 'default_credentials'),
        build_target='benchmarks/XBEN-027-24',
        host_port=18026,
        description='XBEN-027-24',
    ),
    XBOWChallenge(
        id='XBEN-028-24',
        level=2,
        tags=('lfi', 'arbitrary_file_upload'),
        build_target='benchmarks/XBEN-028-24',
        host_port=18027,
        description='XBEN-028-24',
    ),
    XBOWChallenge(
        id='XBEN-029-24',
        level=2,
        tags=('blind_sqli', 'arbitrary_file_upload'),
        build_target='benchmarks/XBEN-029-24',
        host_port=18028,
        description='XBEN-029-24',
    ),
    XBOWChallenge(
        id='XBEN-030-24',
        level=2,
        tags=('cve', 'command_injection'),
        build_target='benchmarks/XBEN-030-24',
        host_port=18029,
        description='XBEN-030-24',
    ),
    XBOWChallenge(
        id='XBEN-031-24',
        level=1,
        tags=('command_injection', 'cve', 'path_traversal'),
        build_target='benchmarks/XBEN-031-24',
        host_port=18030,
        description='XBEN-031-24',
    ),
    XBOWChallenge(
        id='XBEN-032-24',
        level=1,
        tags=('xxe', 'default_credentials'),
        build_target='benchmarks/XBEN-032-24',
        host_port=18031,
        description='XBEN-032-24',
    ),
    XBOWChallenge(
        id='XBEN-033-24',
        level=1,
        tags=('ssrf',),
        build_target='benchmarks/XBEN-033-24',
        host_port=18032,
        description='XBEN-033-24',
    ),
    XBOWChallenge(
        id='XBEN-034-24',
        level=1,
        tags=('cve',),
        build_target='benchmarks/XBEN-034-24',
        host_port=18033,
        description='XBEN-034-24',
    ),
    XBOWChallenge(
        id='XBEN-035-24',
        level=2,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-035-24',
        host_port=18034,
        description='XBEN-035-24',
    ),
    XBOWChallenge(
        id='XBEN-036-24',
        level=1,
        tags=('insecure_deserialization',),
        build_target='benchmarks/XBEN-036-24',
        host_port=18035,
        description='XBEN-036-24',
    ),
    XBOWChallenge(
        id='XBEN-037-24',
        level=1,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-037-24',
        host_port=18036,
        description='XBEN-037-24',
    ),
    XBOWChallenge(
        id='XBEN-038-24',
        level=1,
        tags=('graphql', 'sqli'),
        build_target='benchmarks/XBEN-038-24',
        host_port=18037,
        description='XBEN-038-24',
    ),
    XBOWChallenge(
        id='XBEN-039-24',
        level=1,
        tags=('sqli', 'privilege_escalation'),
        build_target='benchmarks/XBEN-039-24',
        host_port=18038,
        description='XBEN-039-24',
    ),
    XBOWChallenge(
        id='XBEN-040-24',
        level=2,
        tags=('blind_sqli',),
        build_target='benchmarks/XBEN-040-24',
        host_port=18039,
        description='XBEN-040-24',
    ),
    XBOWChallenge(
        id='XBEN-041-24',
        level=1,
        tags=('arbitrary_file_upload', 'command_injection'),
        build_target='benchmarks/XBEN-041-24',
        host_port=18040,
        description='XBEN-041-24',
    ),
    XBOWChallenge(
        id='XBEN-042-24',
        level=1,
        tags=('information_disclosure', 'ssh'),
        build_target='benchmarks/XBEN-042-24',
        host_port=18041,
        description='XBEN-042-24',
    ),
    XBOWChallenge(
        id='XBEN-043-24',
        level=2,
        tags=('idor', 'default_credentials'),
        build_target='benchmarks/XBEN-043-24',
        host_port=18042,
        description='XBEN-043-24',
    ),
    XBOWChallenge(
        id='XBEN-044-24',
        level=1,
        tags=('ssti',),
        build_target='benchmarks/XBEN-044-24',
        host_port=18043,
        description='XBEN-044-24',
    ),
    XBOWChallenge(
        id='XBEN-045-24',
        level=1,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-045-24',
        host_port=18044,
        description='XBEN-045-24',
    ),
    XBOWChallenge(
        id='XBEN-046-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-046-24',
        host_port=18045,
        description='XBEN-046-24',
    ),
    XBOWChallenge(
        id='XBEN-047-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-047-24',
        host_port=18046,
        description='XBEN-047-24',
    ),
    XBOWChallenge(
        id='XBEN-048-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-048-24',
        host_port=18047,
        description='XBEN-048-24',
    ),
    XBOWChallenge(
        id='XBEN-049-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-049-24',
        host_port=18048,
        description='XBEN-049-24',
    ),
    XBOWChallenge(
        id='XBEN-050-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-050-24',
        host_port=18049,
        description='XBEN-050-24',
    ),
    XBOWChallenge(
        id='XBEN-051-24',
        level=2,
        tags=('xss',),
        build_target='benchmarks/XBEN-051-24',
        host_port=18050,
        description='XBEN-051-24',
    ),
    XBOWChallenge(
        id='XBEN-052-24',
        level=1,
        tags=('privilege_escalation', 'business_logic'),
        build_target='benchmarks/XBEN-052-24',
        host_port=18051,
        description='XBEN-052-24',
    ),
    XBOWChallenge(
        id='XBEN-053-24',
        level=1,
        tags=('ssti',),
        build_target='benchmarks/XBEN-053-24',
        host_port=18052,
        description='XBEN-053-24',
    ),
    XBOWChallenge(
        id='XBEN-054-24',
        level=2,
        tags=('privilege_escalation', 'business_logic', 'http_method_tamper'),
        build_target='benchmarks/XBEN-054-24',
        host_port=18053,
        description='XBEN-054-24',
    ),
    XBOWChallenge(
        id='XBEN-055-24',
        level=2,
        tags=('privilege_escalation', 'business_logic'),
        build_target='benchmarks/XBEN-055-24',
        host_port=18054,
        description='XBEN-055-24',
    ),
    XBOWChallenge(
        id='XBEN-056-24',
        level=2,
        tags=('ssti', 'default_credentials'),
        build_target='benchmarks/XBEN-056-24',
        host_port=18055,
        description='XBEN-056-24',
    ),
    XBOWChallenge(
        id='XBEN-057-24',
        level=3,
        tags=('insecure_deserialization',),
        build_target='benchmarks/XBEN-057-24',
        host_port=18056,
        description='XBEN-057-24',
    ),
    XBOWChallenge(
        id='XBEN-058-24',
        level=1,
        tags=('idor',),
        build_target='benchmarks/XBEN-058-24',
        host_port=18057,
        description='XBEN-058-24',
    ),
    XBOWChallenge(
        id='XBEN-059-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-059-24',
        host_port=18058,
        description='XBEN-059-24',
    ),
    XBOWChallenge(
        id='XBEN-060-24',
        level=2,
        tags=('privilege_escalation', 'crypto', 'default_credentials', 'brute_force'),
        build_target='benchmarks/XBEN-060-24',
        host_port=18059,
        description='XBEN-060-24',
    ),
    XBOWChallenge(
        id='XBEN-061-24',
        level=1,
        tags=('lfi',),
        build_target='benchmarks/XBEN-061-24',
        host_port=18060,
        description='XBEN-061-24',
    ),
    XBOWChallenge(
        id='XBEN-062-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-062-24',
        host_port=18061,
        description='XBEN-062-24',
    ),
    XBOWChallenge(
        id='XBEN-063-24',
        level=2,
        tags=('ssti', 'default_credentials'),
        build_target='benchmarks/XBEN-063-24',
        host_port=18062,
        description='XBEN-063-24',
    ),
    XBOWChallenge(
        id='XBEN-064-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-064-24',
        host_port=18063,
        description='XBEN-064-24',
    ),
    XBOWChallenge(
        id='XBEN-065-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-065-24',
        host_port=18064,
        description='XBEN-065-24',
    ),
    XBOWChallenge(
        id='XBEN-066-24',
        level=3,
        tags=('smuggling_desync', 'default_credentials'),
        build_target='benchmarks/XBEN-066-24',
        host_port=18065,
        description='XBEN-066-24',
    ),
    XBOWChallenge(
        id='XBEN-067-24',
        level=1,
        tags=('arbitrary_file_upload', 'command_injection'),
        build_target='benchmarks/XBEN-067-24',
        host_port=18066,
        description='XBEN-067-24',
    ),
    XBOWChallenge(
        id='XBEN-068-24',
        level=2,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-068-24',
        host_port=18067,
        description='XBEN-068-24',
    ),
    XBOWChallenge(
        id='XBEN-069-24',
        level=2,
        tags=('idor', 'privilege_escalation'),
        build_target='benchmarks/XBEN-069-24',
        host_port=18068,
        description='XBEN-069-24',
    ),
    XBOWChallenge(
        id='XBEN-070-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-070-24',
        host_port=18069,
        description='XBEN-070-24',
    ),
    XBOWChallenge(
        id='XBEN-071-24',
        level=1,
        tags=('sqli',),
        build_target='benchmarks/XBEN-071-24',
        host_port=18070,
        description='XBEN-071-24',
    ),
    XBOWChallenge(
        id='XBEN-072-24',
        level=1,
        tags=('privilege_escalation', 'business_logic', 'information_disclosure'),
        build_target='benchmarks/XBEN-072-24',
        host_port=18071,
        description='XBEN-072-24',
    ),
    XBOWChallenge(
        id='XBEN-073-24',
        level=1,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-073-24',
        host_port=18072,
        description='XBEN-073-24',
    ),
    XBOWChallenge(
        id='XBEN-074-24',
        level=1,
        tags=('xss',),
        build_target='benchmarks/XBEN-074-24',
        host_port=18073,
        description='XBEN-074-24',
    ),
    XBOWChallenge(
        id='XBEN-075-24',
        level=2,
        tags=('insecure_deserialization',),
        build_target='benchmarks/XBEN-075-24',
        host_port=18074,
        description='XBEN-075-24',
    ),
    XBOWChallenge(
        id='XBEN-076-24',
        level=1,
        tags=('ssti',),
        build_target='benchmarks/XBEN-076-24',
        host_port=18075,
        description='XBEN-076-24',
    ),
    XBOWChallenge(
        id='XBEN-077-24',
        level=1,
        tags=('xxe', 'arbitrary_file_upload'),
        build_target='benchmarks/XBEN-077-24',
        host_port=18076,
        description='XBEN-077-24',
    ),
    XBOWChallenge(
        id='XBEN-078-24',
        level=2,
        tags=('sqli',),
        build_target='benchmarks/XBEN-078-24',
        host_port=18077,
        description='XBEN-078-24',
    ),
    XBOWChallenge(
        id='XBEN-079-24',
        level=2,
        tags=('lfi',),
        build_target='benchmarks/XBEN-079-24',
        host_port=18078,
        description='XBEN-079-24',
    ),
    XBOWChallenge(
        id='XBEN-080-24',
        level=2,
        tags=('ssti',),
        build_target='benchmarks/XBEN-080-24',
        host_port=18079,
        description='XBEN-080-24',
    ),
    XBOWChallenge(
        id='XBEN-081-24',
        level=2,
        tags=('insecure_deserialization',),
        build_target='benchmarks/XBEN-081-24',
        host_port=18080,
        description='XBEN-081-24',
    ),
    XBOWChallenge(
        id='XBEN-082-24',
        level=2,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-082-24',
        host_port=18081,
        description='XBEN-082-24',
    ),
    XBOWChallenge(
        id='XBEN-083-24',
        level=1,
        tags=('sqli',),
        build_target='benchmarks/XBEN-083-24',
        host_port=18082,
        description='XBEN-083-24',
    ),
    XBOWChallenge(
        id='XBEN-084-24',
        level=1,
        tags=('privilege_escalation', 'jwt', 'information_disclosure'),
        build_target='benchmarks/XBEN-084-24',
        host_port=18083,
        description='XBEN-084-24',
    ),
    XBOWChallenge(
        id='XBEN-085-24',
        level=1,
        tags=('privilege_escalation', 'business_logic'),
        build_target='benchmarks/XBEN-085-24',
        host_port=18084,
        description='XBEN-085-24',
    ),
    XBOWChallenge(
        id='XBEN-086-24',
        level=2,
        tags=('ssti',),
        build_target='benchmarks/XBEN-086-24',
        host_port=18085,
        description='XBEN-086-24',
    ),
    XBOWChallenge(
        id='XBEN-087-24',
        level=3,
        tags=('xss',),
        build_target='benchmarks/XBEN-087-24',
        host_port=18086,
        description='XBEN-087-24',
    ),
    XBOWChallenge(
        id='XBEN-088-24',
        level=3,
        tags=('default_credentials', 'race_condition'),
        build_target='benchmarks/XBEN-088-24',
        host_port=18087,
        description='XBEN-088-24',
    ),
    XBOWChallenge(
        id='XBEN-089-24',
        level=2,
        tags=('privilege_escalation', 'business_logic'),
        build_target='benchmarks/XBEN-089-24',
        host_port=18088,
        description='XBEN-089-24',
    ),
    XBOWChallenge(
        id='XBEN-090-24',
        level=2,
        tags=('idor', 'privilege_escalation'),
        build_target='benchmarks/XBEN-090-24',
        host_port=18089,
        description='XBEN-090-24',
    ),
    XBOWChallenge(
        id='XBEN-091-24',
        level=2,
        tags=('jwt', 'privilege_escalation'),
        build_target='benchmarks/XBEN-091-24',
        host_port=18090,
        description='XBEN-091-24',
    ),
    XBOWChallenge(
        id='XBEN-092-24',
        level=2,
        tags=('insecure_deserialization', 'arbitrary_file_upload'),
        build_target='benchmarks/XBEN-092-24',
        host_port=18091,
        description='XBEN-092-24',
    ),
    XBOWChallenge(
        id='XBEN-093-24',
        level=3,
        tags=('ssti',),
        build_target='benchmarks/XBEN-093-24',
        host_port=18092,
        description='XBEN-093-24',
    ),
    XBOWChallenge(
        id='XBEN-094-24',
        level=2,
        tags=('command_injection',),
        build_target='benchmarks/XBEN-094-24',
        host_port=18093,
        description='XBEN-094-24',
    ),
    XBOWChallenge(
        id='XBEN-095-24',
        level=1,
        tags=('blind_sqli',),
        build_target='benchmarks/XBEN-095-24',
        host_port=18094,
        description='XBEN-095-24',
    ),
    XBOWChallenge(
        id='XBEN-096-24',
        level=1,
        tags=('xxe',),
        build_target='benchmarks/XBEN-096-24',
        host_port=18095,
        description='XBEN-096-24',
    ),
    XBOWChallenge(
        id='XBEN-097-24',
        level=2,
        tags=('path_traversal',),
        build_target='benchmarks/XBEN-097-24',
        host_port=18096,
        description='XBEN-097-24',
    ),
    XBOWChallenge(
        id='XBEN-098-24',
        level=1,
        tags=('lfi', 'information_disclosure', 'path_traversal'),
        build_target='benchmarks/XBEN-098-24',
        host_port=18097,
        description='XBEN-098-24',
    ),
    XBOWChallenge(
        id='XBEN-099-24',
        level=2,
        tags=('idor',),
        build_target='benchmarks/XBEN-099-24',
        host_port=18098,
        description='XBEN-099-24',
    ),
    XBOWChallenge(
        id='XBEN-100-24',
        level=2,
        tags=('nosqli', 'graphql'),
        build_target='benchmarks/XBEN-100-24',
        host_port=18099,
        description='XBEN-100-24',
    ),
    XBOWChallenge(
        id='XBEN-101-24',
        level=3,
        tags=('crypto',),
        build_target='benchmarks/XBEN-101-24',
        host_port=18100,
        description='XBEN-101-24',
    ),
    XBOWChallenge(
        id='XBEN-102-24',
        level=1,
        tags=('default_credentials', 'business_logic'),
        build_target='benchmarks/XBEN-102-24',
        host_port=18101,
        description='XBEN-102-24',
    ),
    XBOWChallenge(
        id='XBEN-103-24',
        level=2,
        tags=('information_disclosure', 'idor', 'crypto', 'privilege_escalation'),
        build_target='benchmarks/XBEN-103-24',
        host_port=18102,
        description='XBEN-103-24',
    ),
    XBOWChallenge(
        id='XBEN-104-24',
        level=2,
        tags=('ssti', 'default_credentials'),
        build_target='benchmarks/XBEN-104-24',
        host_port=18103,
        description='XBEN-104-24',
    ),
]


# Lookup by id — used by the runner's ``--ids`` flag.
BY_ID: dict[str, XBOWChallenge] = {ch.id: ch for ch in PILOT}


def resolve(ids: list[str]) -> list[XBOWChallenge]:
    """Return the XBOWChallenge objects for ``ids``, in input order.

    Unknown ids raise ``KeyError`` with a helpful message.
    """
    out: list[XBOWChallenge] = []
    for cid in ids:
        if cid not in BY_ID:
            raise KeyError(
                f"Unknown XBOW challenge {cid!r}. "
                f"Available: {', '.join(BY_ID)}"
            )
        out.append(BY_ID[cid])
    return out


__all__ = ["XBOWChallenge", "PILOT", "BY_ID", "resolve"]
