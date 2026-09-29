# PIM Automation review — 2026-09-29

**Assessment:** useful operator tooling, but not ready for unattended privileged provisioning.
Fix the safety gaps before adding a GUI or more automation.

## P1 remediation in the working version — 2026-09-29

The five P1 paths below have candidate fixes and behavioral regressions in
`tests/identity/Invoke-P1SafetyTests.ps1`. The original findings table and JSON evidence are
retained as the pre-fix assessment; they do not describe the current outcome of every probe.

- Standing group writes check group policy assignments and reject PIM-managed or unknown governance in both profile and clone paths, including at the write boundary.
- Failed relevant reads refuse apply; ARM and Graph paging is checked, failed active-group reads remain unknown, and expiring `Assigned` schedules are not converted into standing access.
- Conditional RBAC and Azure eligibility copies are blocked; conditional target assignments cannot be silently replaced by unconditional profile grants.
- Profile scopes are validated after alias resolution. Roles are resolved to canonical IDs and checked for access-administration permissions before planning and granting. Custom standing roles must be read-only.
- Direct cloning requires `-TenantId`; the launcher supplies its bound configuration tenant. Graph/Azure contexts, subscription inventory, paging hosts, and ARM write scopes are checked against that public-cloud tenant.

The focused suite includes legitimate Reader and ordinary-group controls, failure classes, equivalent
role/scope forms, and full mocked clone runs. No live tenant validation has been performed.
Ordinary groups may convey privilege outside PIM; these changes do not inventory all such access.
The remaining P2 items (duration/policy safeguards, final audit outcomes, interactive defaults,
and discovery completeness) still require work. The Graph scope-array defect and page-cap
success defect were also addressed because the new guards depend on those paths.

## Privacy cleanup completed

Reviewed all 12 supplied files: scripts, tenant profiles, tests, and runbook. Removed identifiable
organization names, tenant/management-group GUID, account aliases, email domains, internal group
names, old repository names and identifying operational anecdotes. Renamed the tenant folder to
`example`, supplied a zero GUID and synthetic group names, and changed the branded output path to
`PIM-Automation/cadm-clone`. Added `.gitignore` exclusions for real tenant bindings, audit exports
and caches. Removed the two bytecode files generated during baseline testing because they contained
the original source strings.

No credentials or private keys were found in the supplied text. This is a scoped inspection, not
proof about external files or historical copies. No `.git` directory was present. Other checkouts,
prior exports, local-app-data logs and conversation/tool logs are outside this cleanup. Runtime
audit exports will still contain identity data. `.gitignore` does not remove already-published data.
The example requires configuration before use. `Cadm` script/function names remain for compatibility.
Microsoft product names and public project/vendor names in this comparison are intentional references.

## Existing strengths

- Clone/profile previews, typed apply confirmation, and readable explanations for skipped grants.
- Distinction between several standing, eligible, activated and group-derived access paths.
- Tenant settings separated from the engine; data-only profiles; ambiguous group names rejected.
- Disabled-target and same-source/target checks in cloning; existing-assignment checks.
- Bounded group/directory eligibility defaults and separate consent families.

## Original findings, in priority order

At the original review, cleanup did **not** fix these access-engine issues. Offline probes validate local behavior;
no live tenant write or successful exploitation was attempted.

| Priority | Finding and source | Evidence / recommended correction |
|---|---|---|
| P1 | **Standing membership can bypass PIM.** `CadmProfile.ps1: Resolve-ProfilePlan` checks sync and `isAssignableToRole`, but not PIM enrollment for `GroupMemberships`. | A non-role-assignable PIM group produced `CREATE` without querying PIM. Check each group's governance policy; block PIM-managed membership and unreadable policy. Inspect privileged Azure/app access conveyed by ordinary groups too. |
| P1 | **Failed reads can turn temporary access into standing access.** `CadmAccess.Core.ps1: Get-PimGroupsFor`, `Get-PimActivatedFor`; profile RBAC planner. | Active-group read failure still returned `Ok=True`. A throttled Azure activation read returned `Denied=False` with an empty map. The clone loop can then treat the assignment as standing. A denied profile RBAC read became `CREATE`. Every reader needs complete/empty/unknown states; refuse apply on incomplete relevant reads. |
| P1 | **RBAC cloning drops conditions.** `Copy-CadmAccess.ps1: RBAC plan/create`. | `condition` and `conditionVersion` are neither carried nor sent, so conditional access can become unconditional. Preserve/compare them, or block such cloning. Also distinguish time-limited active `Assigned` schedules from genuinely permanent assignments. |
| P1 | **Template restrictions are bypassable.** `CadmProfile.ps1: Assert-ProfileSafe`, `Resolve-CadmScope`. | The public Owner role GUID passed a display-name-only restriction. A scope alias resolving to `/` passed. Resolve final role ID and scope before validation; classify custom-role effective permissions and enforce allowed scope boundaries. |
| P1 | **Tenant isolation is incomplete.** `Test-MgConnected`, `Connect-GraphIfNeeded`, `Get-Subscriptions`, and direct clone entry point. | Any Graph tenant is accepted; authentication receives no tenant; subscription inventory retains other tenants and discards tenant metadata. Direct clone bypasses launcher binding. Require explicit tenant/cloud everywhere, bind both sessions, filter inventory, and recheck before writing. Wrong-context acceptance was reproduced, not a cross-tenant write. |
| P2 | **Fresh authentication loses required scopes.** Launcher appends directory scopes, but core rebuilds from group lists; apply also iterates individual scope strings. | Mocked fresh apply requested only `PrivilegedAccess.ReadWrite.AzureADGroup`. Pass immutable required scope sets into authentication; preserve arrays and probe every required plane. Directory-only operations should not require the group plane. Include policy-read permissions. |
| P2 | **Discovery can be incomplete while reporting success.** Core paging and group fallback. | Several readers use only the first page; the Graph helper returns success after its 100-page cap despite a next page. Fallback misses eligible-only non-role-assignable groups and caches candidates across principals. Follow all pages or report incomplete; query named profile groups directly; make fallback inventory coverage explicit. |
| P2 | **Audit records intent, not completion.** Both entry points write JSON before confirmation/execution. | Clone `applied=true` means a flag was supplied, even if cancelled. No per-grant final status, IDs or read-back verification. Journal planned/approved/requested/verified/failed/cancelled states, actual duration, actor, tenant, profile version and request/assignment IDs. |
| P2 | **Activation safeguards are advice.** Global Administrator profile and expiration helpers. | Approval/MFA/approvers/activation duration are not verified. Explicit group duration bypasses policy clamping: mocked 30-day maximum still yielded 365 days. Validate activation prerequisites and all durations during planning. Server rejection can leave earlier grants applied. |
| P2 | **Interactive mode weakens defaults.** Core `$Interactive` handling. | It implies apply, enables root-scope candidates and active-to-eligible conversion, and offers `all`. Keep selection as preview; require apply separately and exclude high-risk grants from `all`. |

Microsoft supports PIM for both role-assignable and non-role-assignable groups, so that flag
cannot determine PIM enrollment. [Microsoft PIM guidance](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/just-in-time-access-to-groups-and-conditional-access-integration-in-privileged-i/2466926).
Azure CLI supports assignment conditions; Graph supports tenant/cloud-specific authentication.
[Azure CLI reference](https://learn.microsoft.com/en-us/cli/azure/role/assignment?view=azure-cli-lts),
[Graph authentication](https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands).

Other correctness work: reject unknown profile keys and duplicate tenant bindings; use exact
UPN/object ID for unattended writes rather than fallback prefix matching; escape OData; deduplicate
entries; compare schedule dates and member/owner independently; handle dynamic groups explicitly.
Generated `Add-ADGroupMember` commands interpolate unescaped display names and assume a UPN prefix
is the AD identity. Export structured data and resolve immutable AD identifiers before execution.

## Template improvements

The best product direction is **turn a reference user's access into a reviewed, portable job
template, then verify the target received exactly the approved access**.

1. **Discover → select → normalize → preview → save.** Import one user or a peer cohort. Show
   direct, inherited, eligible, activated and standing access separately. Common access is a
   candidate for review, not evidence it is appropriate. Never auto-publish inferred templates.
2. **Three separate layers:** portable job template, tenant bindings and mandatory guardrails.
   Use logical names such as `production-reader`; bind them to tenant-local IDs/scopes. Resolve
   canonical IDs at runtime. A GUID alone does not make a custom role/group portable.
3. **Strict schema:** version, owner, reviewer, review/expiry dates, risk tier, allowed clouds,
   parameter limits, scope constraints, conditions and required activation policy. Validate unknown
   keys, duplicates, inheritance cycles, conflicts and ISO durations offline.
4. **Composable task templates:** optional Reader baseline plus narrow workload modules. Make
   tenant-root Reader optional; a workload admin does not necessarily need estate-wide visibility.
5. **A guided builder:** browse roles/groups, display their effective privilege and activation
   policy, and export a sanitized draft. Keep discovery inventories separate from reusable examples.

## Safety, automation and usefulness

- Use one plan/apply engine for cloning and profiles. Resolve identity, role, scope, conditions,
  policy and actual duration before approval. Apply a saved plan bound to tenant, target, template
  hash and expiry; reject stale state immediately before writes. A hash is not approval—use a
  trusted approval record or signature, outside the process's own `-Force` switch.
- Add Pester behavior tests with mocked APIs and disposable-tenant integration tests. Cover
  403/429, pagination, context mismatch, pending approval, duplicate requests, conditional RBAC,
  cancellation and revocation between plan/apply. Source-string tests missed real behavioral gaps.
- Provide preflight diagnostics, structured output/exit codes, non-interactive authentication,
  `Retry-After` handling, stable operation IDs, resumable journals and per-target locks. Use workload
  federation/managed identity where each API supports it; validate delegated and application
  authorization separately. Keep each tenant's credentials, state and execution isolated.
- Read back each grant. Record partial completion precisely. Start additive-only. Reconciliation
  and rollback may remove only tool-owned assignments created by that run, after checking they
  were not independently changed; never remove pre-existing access as a generic rollback.
- Add an external audit destination with retention/access controls and redacted support exports.
- Complete plane coverage: profiles lack direct Azure-resource PIM eligibilities; cloning lacks
  directory-role eligibilities. Neither path is a complete copy of all access a user may hold.
- Add drift reports, renewal/review queues, expiring-access notifications and job-transfer diffs.
  Report excess access without silently deleting it.
- Package as a module with explicit context objects, pinned dependencies and a manifest, replacing
  shared script variables. Test PowerShell 5.1 and 7; validate Linux/macOS before claiming support.
- Support public/sovereign endpoints, subscription allowlists, scope mappings, custom-role mappings,
  tenant-scoped caches and private configuration import. Add UI only after the engine is safe.
- Before public distribution, add a release/sanitization check, changelog and approved license and
  provenance. Removing identifying details does not establish redistribution rights.

## Comparable tools

Primary sources checked on 2026-09-29. Counts are what the retrieved GitHub pages showed, not
market share or proof of production adoption. Product capabilities below are documented claims,
not hands-on validation. The community projects have modest visible traction; no market-leading
popularity is claimed.

| Tool | Comparison / traction | Standout feature |
|---|---|---|
| **[EasyPIM + Orchestrator](https://github.com/kayasax/EasyPIM)** | Closest open-source equivalent; 235 stars, 27 forks on retrieved page. | Declarative policies AND assignments across Azure, Entra and groups, with drift detection. Its [templates](https://kayasax.github.io/EasyPIM/template-guide.html) support reusable policies, scoped overrides, resolved policy output, previews and OIDC CI/CD. Evaluate before rebuilding equivalent API plumbing. |
| **[Entra Entitlement Management](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview)** | Native Microsoft lifecycle option; no comparable usage count established here. | Requestable access packages with approval, reviews and expiry. [Azure RBAC packages](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-azure-role-assignments) now support active/eligible built-in/custom roles and require Governance or Entra Suite licensing. Direct [Entra-role packages remain Preview](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-roles). This is the native buy-versus-build baseline. |
| **[EntraOps](https://github.com/Cloud-Architekt/EntraOps)** | Adjacent assessment/governance tool; 328 stars, 37 forks. | Enterprise Access Model privilege classification across Microsoft authorization systems, change history and reporting. Borrow the effective-privilege classification for template reviews. |
| **[PIMActivation](https://github.com/Noble-Effeciency13/PIMActivation)** | End-user activation, not provisioning; 67 stars, 9 forks. | Saved activation profiles, bulk/scheduled activation, reduced Azure scope and policy-aware authentication. Borrow the easy daily workflow without confusing activation with eligibility provisioning. |
| **[BeyondTrust Entitle](https://www.beyondtrust.com/products/entitle)** | Commercial cross-platform access governance; adoption not independently quantified. | One request bundles permissions across systems, with Teams/Slack/Jira requests. [Approval workflows](https://docs.beyondtrust.com/entitle/docs/approval-workflows) include resource owners, on-call schedules and external webhooks. Borrow task-based bundles and delegated approvals. |

**Recommendation:** benchmark EasyPIM, and evaluate native access packages before building a
broader lifecycle platform. This project's useful differentiator would be reviewed reference-user
imports, portable job templates, clear privilege explanations and verified per-user outcomes.

## Delivery order and verification

1. Close P1 findings; repair authentication and discovery; add runtime regression tests and final
   audit outcomes.
2. Add strict template schema, logical bindings, guided imports, composition, saved plans and
   complete plane coverage.
3. Add approved automation, resumable execution, drift/renewal reporting, then self-service where
   native access packages do not fit.

Original and post-cleanup suites: **95 Python source-text tests passed**. All 10 PowerShell
source/data files parse, and clone script help loads, in PowerShell 7 and Windows PowerShell 5.1.
`tests/identity/Invoke-ReviewProbes.ps1` reproduces 11 gaps with synthetic data and mocked APIs;
both editions produced identical observations. Evidence: [PowerShell 7](review-probes-pwsh.json)
and [Windows PowerShell](review-probes-windows-powershell.json). These are demonstrations of open
issues, not 11 successful safety checks. No Azure login, Graph sign-in, grant, group change or publication was performed.
Live authorization, licensing, propagation, successful provisioning and rollback remain untested.
