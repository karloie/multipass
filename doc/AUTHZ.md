# Auth and Authorization

Multipass separates external identity from internal access roles.

## Authentication

Multipass accepts two caller types:

- browser users authenticated with OIDC and stored in a local session
- API callers authenticated from bearer tokens or trusted proxy headers

Both paths produce the same internal identity model:

- stable identity: `ID`, `PrincipalID`, `Email`
- user labels: `Username`, `Name`
- external groups from the IdP or JWT: `Groups`

## Authorization

Authorization is evaluated from three inputs:

- external groups from the IdP or JWT
- internal roles derived from `authz.roleMappings`
- temporary elevated roles granted by PIM

The evaluator then resolves final namespace access from `authz.groupMappings`.

Current permission model:

- `ExternalGroups`: raw incoming groups
- `InternalRoles`: Multipass roles such as `dev`, `devops`, `admin`, `man`
- `ElevatedRoles`: temporary roles granted after approval
- `AllowedNamespaces`: final namespace scope used by the proxy

## Internal Taxonomy

Current internal roles:

- `dev`: baseline developer access
- `devops`: broader non-prod operational access
- `admin`: platform and prod administration
- `man`: audit, warehouse, statistics, and oversight access

Management and approval are separate concerns:

- external AD group `ManagerGroup` is the approval source group
- internal `leader` is the intended normalized management concept if leader-specific permissions are added later
- `ManagerGroup` should not imply `admin`
- `man` should not imply `admin`

## Recommended External Mapping

Based on the current AD group analysis, the intended mapping is:

- `DeveloperGroup` -> `dev`
- `PlatformBaseGroup` -> `devops`
- `PlatformDevAdminGroup` -> `devops`
- `PlatformProdAdminGroup` -> `admin`
- `PlatformToolsAdminGroup` -> `admin`
- `PlatformSuperAdminGroup` -> `admin`

`PlatformTeam` is a team scope marker, not by itself the best source of technical permissions when the more specific platform role groups are present.

## PIM

PIM adds temporary internal roles through a browser-only approval flow:

- user requests a temporary role at `/pim`
- approver approves or denies at `/approve-pim`
- approved requests become temporary `ElevatedRoles`
- authz evaluates those elevated roles together with the normal roles

Current PIM protections:

- browser auth required
- same-origin checks on POST
- self-approval blocked
- role duration bounded by config

## Important Current Limitation

Today `pim.roles[].approverGroups` is matched as any-of-these-groups.

That is enough for:

- explicit named approvers
- broad group-based approvers such as `ManagerGroup`

It is not enough for team-scoped approval rules such as:

- must be in `ManagerGroup`
- and must be in `PlatformTeam`

That team-scoped approval model is the next logical improvement for PIM.