"""Target profiles for the IDOR scanner.

Extend this file to add new targets. Each profile defines how the scanner
interacts with a specific website. All fields are optional — empty fields
trigger auto-discovery.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from prometheus.agents.browser_session import TargetProfile


# Predefined target profiles
# Add new targets here following the same format
def _build_target_profiles() -> dict[str, "TargetProfile"]:
    from prometheus.agents.browser_session import TargetProfile  # noqa: PLC0415

    return {
        "syfe": TargetProfile(
            name="Syfe",
            base_url="https://www.syfe.com",
            signup_path="/create-account",
            login_path="/login",
            pages_to_scan=["/", "/dashboard", "/portfolio", "/transactions"],
        ),
        "bullish": TargetProfile(
            name="Bullish Exchange",
            base_url="https://simnext.bullish-test.com",
            signup_path="/register",
            login_path="/login",
            pages_to_scan=["/", "/dashboard", "/wallet", "/orders", "/profile"],
        ),
        "opensea": TargetProfile(
            name="OpenSea",
            base_url="https://opensea.io",
            signup_path="/account/signup",
            login_path="/account/login",
            pages_to_scan=["/", "/account", "/collections"],
        ),
        "etoro": TargetProfile(
            name="eToro",
            base_url="https://www.etoro.com",
            signup_path="/register",
            login_path="/login",
            pages_to_scan=["/", "/portfolio", "/markets", "/account"],
        ),
        "launchdarkly": TargetProfile(
            name="LaunchDarkly",
            base_url="https://app.launchdarkly.com",
            signup_path="",
            login_path="/login",
            pages_to_scan=["/", "/projects", "/features", "/environments", "/account"],
            email_domain="@example.com",
            api_patterns=[
                r"/api/v2/",
                r"/internal/",
                r"/private/",
                r"/projects?",
                r"/environments?",
                r"/flags?",
                r"/features?",
                r"/contexts?",
                r"/segments?",
                r"/experiments?",
                r"/users?",
                r"/members?",
                r"/roles?",
            ],
            id_param_names=[
                "id",
                "projectId",
                "project_id",
                "envId",
                "env_id",
                "environmentId",
                "environment_id",
                "flagId",
                "flag_id",
                "contextId",
                "context_id",
                "memberId",
                "member_id",
                "orgId",
                "org_id",
                "key",
            ],
        ),
    }


TARGET_PROFILES = _build_target_profiles()
