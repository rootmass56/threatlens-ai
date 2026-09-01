from api.rbac import ALL_PERMISSIONS, ROLE_DEFINITIONS, Permission, permissions_for_roles


def test_six_governed_roles_have_explicit_permissions() -> None:
    assert set(ROLE_DEFINITIONS) == {
        "viewer",
        "analyst",
        "senior_analyst",
        "incident_commander",
        "rule_engineer",
        "administrator",
    }
    assert ROLE_DEFINITIONS["administrator"].permissions == ALL_PERMISSIONS
    assert Permission.USER_MANAGE not in ROLE_DEFINITIONS["viewer"].permissions
    assert Permission.ATTACK_SYNC in ROLE_DEFINITIONS["rule_engineer"].permissions
    assert Permission.INCIDENT_CLOSE in ROLE_DEFINITIONS["incident_commander"].permissions


def test_permission_union_is_deterministic() -> None:
    permissions = permissions_for_roles(frozenset({"viewer", "analyst"}))
    assert Permission.ANALYSIS_READ in permissions
    assert Permission.ANALYSIS_CREATE in permissions
    assert Permission.USER_MANAGE not in permissions


def _principal_for(role_name: str):
    from api.security import Principal

    permissions = ROLE_DEFINITIONS[role_name].permissions
    return Principal(
        user_uuid=f"{role_name}-uuid",
        username=role_name,
        display_name=role_name.replace("_", " ").title(),
        roles=frozenset({role_name}),
        permissions=permissions,
        token_jti="test-token",
    )


def test_incident_object_authorization_enforces_assignment_and_closure() -> None:
    from api.routes.incidents import _can_modify

    viewer = _principal_for("viewer")
    analyst = _principal_for("analyst")
    senior = _principal_for("senior_analyst")
    commander = _principal_for("incident_commander")
    rule_engineer = _principal_for("rule_engineer")
    administrator = _principal_for("administrator")

    assert not _can_modify(viewer, {"assignee": None})
    assert _can_modify(analyst, {"assignee": None})
    assert _can_modify(analyst, {"assignee": "analyst"})
    assert not _can_modify(analyst, {"assignee": "another-analyst"})
    assert not _can_modify(analyst, {"assignee": "analyst"}, closing=True)
    assert _can_modify(senior, {"assignee": "another-analyst"})
    assert not _can_modify(senior, {"assignee": "another-analyst"}, closing=True)
    assert _can_modify(commander, {"assignee": "another-analyst"})
    assert _can_modify(commander, {"assignee": "another-analyst"}, closing=True)
    assert not _can_modify(rule_engineer, {"assignee": None})
    assert _can_modify(administrator, {"assignee": "another-analyst"})
    assert _can_modify(administrator, {"assignee": "another-analyst"}, closing=True)
