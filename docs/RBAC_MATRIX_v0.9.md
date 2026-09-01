# ThreatLens AI v0.9 RBAC Matrix

## Permission catalogue

| Permission | Meaning |
|---|---|
| `analysis:read` | View analysis history and normalized results |
| `analysis:create` | Upload and execute analysis |
| `incident:read` | View incident queue and case details |
| `incident:update:self` | Update unassigned or self-assigned incidents |
| `incident:update:any` | Update any incident object |
| `incident:assign` | Assign incidents to another analyst |
| `incident:close` | Resolve or mark incidents false-positive |
| `note:create` | Add investigation notes |
| `evidence:create` | Register case evidence |
| `audit:read` | View audit history |
| `rule:read` | View governed detection rules and quality |
| `rule:manage` | Reserved for future controlled rule changes |
| `attack:read` | View ATT&CK catalogues and mappings |
| `attack:sync` | Synchronize official ATT&CK data |
| `graph:read` | View persistent correlation graphs |
| `report:read` | Generate and download incident reports |
| `user:read` | View user and role administration data |
| `user:manage` | Create and update user accounts |
| `system:read` | View system security posture |
| `docs:view` | Retrieve protected OpenAPI JSON |

## Role matrix

| Permission | Viewer | Analyst | Senior analyst | Incident commander | Rule engineer | Administrator |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Analysis read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Analysis create |  | ✓ | ✓ | ✓ |  | ✓ |
| Incident read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Update self/unassigned |  | ✓ | ✓ | ✓ |  | ✓ |
| Update any case |  |  | ✓ | ✓ |  | ✓ |
| Assign other analyst |  |  | ✓ | ✓ |  | ✓ |
| Close/false-positive |  |  |  | ✓ |  | ✓ |
| Add note/evidence |  | ✓ | ✓ | ✓ |  | ✓ |
| Audit read |  |  | ✓ | ✓ | ✓ | ✓ |
| Rule read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Rule manage |  |  |  |  | ✓ | ✓ |
| ATT&CK read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ATT&CK sync |  |  |  |  | ✓ | ✓ |
| Graph read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Report read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| User read/manage |  |  |  |  |  | ✓ |
| System read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Protected API docs |  |  |  |  |  | ✓ |

## Object-level incident rules

Route permission alone is insufficient for case mutation:

1. Viewer and rule-engineer roles cannot mutate incidents.
2. An analyst may update an unassigned incident or one assigned to the same normalized username.
3. An analyst cannot assign a case to a different user.
4. A senior analyst may update and assign any case but cannot resolve or mark it false-positive.
5. An incident commander may update, assign and close any case.
6. An administrator may perform all case operations.
7. Notes and evidence require their own permissions and the same object-level case access.

## Administration safety rules

- The current administrator cannot disable its own account.
- The current administrator cannot remove its own administrator role.
- The last active administrator cannot be disabled or stripped of the administrator role.
- Role, password and active-state changes invalidate existing sessions.
- Duplicate roles and unknown role names are rejected.
