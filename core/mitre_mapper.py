"""Deprecated compatibility mappings retained for pre-v0.7 callers.

Production detection and ATT&CK coverage use governed YAML rule mappings plus the
official STIX-backed ATT&CK catalogue. New code must not depend on this module.
"""

MITRE_MAPPING = {
    "multiple_failed_logins": {
        "tactic": "Credential Access",
        "technique": "Password Guessing",
        "technique_id": "T1110.001",
        "description": "Repeated authentication failures may indicate password guessing.",
        "recommendation": (
            "Validate the source, enforce MFA, review targeted identities, and block confirmed "
            "malicious infrastructure."
        ),
    },
    "successful_login_after_failures": {
        "tactic": "Credential Access",
        "technique": "Password Guessing",
        "technique_id": "T1110.001",
        "description": (
            "A successful authentication after repeated failures may indicate compromised "
            "credentials."
        ),
        "recommendation": (
            "Validate the login, rotate credentials if suspicious, revoke sessions, and review "
            "endpoint and network telemetry."
        ),
    },
    "suspicious_sudo_command": {
        "tactic": "Privilege Escalation",
        "technique": "Sudo and Sudo Caching",
        "technique_id": "T1548.003",
        "description": "Sensitive sudo execution may indicate abuse of an elevation mechanism.",
        "recommendation": (
            "Review authorization, command context, affected files, shell history, and related "
            "privileged activity."
        ),
    },
    "invalid_user_enumeration": {
        "tactic": "Discovery",
        "technique": "Account Discovery",
        "technique_id": "T1087",
        "description": "Repeated invalid-account attempts may indicate account discovery.",
        "recommendation": (
            "Review targeted names, monitor the source, tune authentication controls, and block "
            "confirmed malicious activity."
        ),
    },
}


def get_mitre_mapping(detection_name: str) -> dict[str, str]:
    """Return a legacy compatibility mapping for historical callers only."""

    fallback = {
        "tactic": "Unknown",
        "technique": "Unknown",
        "technique_id": "N/A",
        "description": "No validated ATT&CK mapping is available.",
        "recommendation": "Review the alert manually and validate the available evidence.",
    }
    return dict(MITRE_MAPPING.get(detection_name, fallback))
