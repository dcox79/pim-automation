# Profile verification, audit results, and broader export coverage

These changes apply to both profile entry points:
- Invoke-CadmAccess.ps1 -Mode profile
- Start-CadmWorkflow.ps1 -Action Apply

The older clone/interactive-clone engine retains its separate behavior and audit format.
No live permissions were granted while implementing or testing these changes.

## Generated descriptions

New exports describe the actual eligible roles, scopes, and expiry dates or durations.
For example: "Eligible Owner at tenant root management group; expires 2027-06-01 14:41:03 UTC. Requires PIM activation."
The filename key remains the operator's chosen key. A single Azure-role export gets a display
name such as "Example Tenant Owner via PIM". Mixed profiles summarize each entry or plane counts.
Descriptions are generated at export time; update the description if you later edit the template.

## Broader discovery

Default export stays Azure-resource-only through accessible subscriptions, using Azure CLI/ARM.
Opt in to broader reads; every requested query must succeed before a grant template is saved.

- AdditionalScopes accepts canonical ARM scopes or configured tenant scope tokens.
- IncludeManagementGroups lists and queries accessible management groups directly. It also works
  when no subscriptions are accessible, provided at least one management-group scope is readable.
- ExportPlanes AzureResource,Group,DirectoryRole selects direct eligible assignments in all three
  planes. Group and directory reads require an appropriate Graph session.
- IncludeGroupDerivedAccess adds a read-only report under Export.GroupDerivedAccess. It records
  current direct/transitive group membership, selected PIM member eligibility, and the Azure and/or
  directory role assignments and eligibilities held by those groups. It never creates direct user
  grants from group permissions. Group owner eligibility is not treated as membership.
- QueriedScopes, SubscriptionIds, Planes, and the coverage text identify what was actually queried.
- If no direct eligibility exists and group coverage was requested, only a .coverage.json report
  is saved. An empty grant profile is not created.

Example, without Graph PowerShell:

~~~powershell
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode export -SourceUser 'source@example.com' -ProfileName 'owner-wide' -ExportPlanes AzureResource -IncludeManagementGroups -AdditionalScopes 'root-mg' -ConnectGraph:$false
~~~

Example with consented Graph read permissions:

~~~powershell
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode export -SourceUser 'source@example.com' -ProfileName 'all-pim' -ExportPlanes AzureResource,Group,DirectoryRole -IncludeManagementGroups -IncludeGroupDerivedAccess
~~~

The guided workflow Import action accepts the same coverage flags and ExportPlanes, then asks which
direct eligibility entries to include. If a generated description is wanted, leave its description
prompt blank. Evidence about indirect access is retained separately.

The extra group-membership read requests User.Read.All on a new Graph connection; directory group
assignment reporting additionally requests RoleManagement.Read.Directory. Existing sessions are
not silently upgraded. Missing consent/read access causes an explicit error, not a partial-success
template. The Azure-only options do not require a Graph PowerShell connection.

Coverage is broader, not exhaustive. Eligible nested-group paths, hidden memberships without
the required consent, deny assignments, effective condition evaluation, and inaccessible scopes
are not resolved. Group role-assignment records do not establish whether access is permanent.
Direct administrative-unit/app-scoped directory eligibility remains unsupported and is refused.
Group-derived evidence is informational, not proof that a user can activate or exercise a role.

API references:
- [Management groups list](https://learn.microsoft.com/en-us/rest/api/managementgroups/management-groups/list?view=rest-managementgroups-2020-05-01)
- [User transitive memberships](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0)
- [Directory role assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0)

## Verify after applying

Both profile commands now verify all five supported profile planes with direct reads:
Azure PIM, group PIM, directory PIM, standing Azure RBAC, and direct group membership.
They check the exact principal, role or member/owner type, and scope.
For newly submitted eligibilities they also compare the actual start and end with the schedule
submitted at the write boundary, allowing only two seconds of service timestamp rounding.
A wrong expiry, condition, or duplicate matching schedule is a mismatch, never success.
An Azure eligibility must also be Provisioned. Graph eligibility-instance presence is its
read-back evidence; the tool does not invent an Azure provisioning status for Graph.

Existing assignments are Retained, with observed dates recorded; they are not renewed.
A successfully submitted request is not sufficient for a Verified run.
Read errors are Unknown; absent/not-yet-provisioned instances are Pending.
VerificationAttempts (default 3, maximum 10) and VerificationDelaySeconds (default 5, maximum 30)
control bounded read-only retries. Writes are not automatically retried.

PendingOrUnknown or Partial returns a nonzero exit code. Check the recorded request/assignment
IDs and observed state before retrying a write. No automatic rollback is attempted.

## Audit results

Each planned profile run uses a unique directory containing review.json.
After confirmation, submissions.json is flushed before each grant and updated afterwards.
outcome.json records the final run state and independent read-back evidence.

Records include the actor, tenant, target, profile hash/version where available, timestamps,
plan, per-entry submission state, errors, service receipts/request IDs where available,
assignment IDs, observed dates, and verification results. Group membership adds have no
assignment/request ID from the existing API; their group/member IDs and read-back are recorded.
Cancelled and refused post-plan runs update review.json and perform no writes.
Preview runs also have a review record. Failures before a plan is produced remain terminal
preflight errors; they do not perform grants.

Both commands recheck configuration, identity and the live plan after confirmation.
A mismatch refuses execution. The guided command additionally enforces its existing reviewed
metadata lifecycle; the compatibility profile command does not add that requirement.
Pre-existing and unsubmitted entries remain visible instead of being omitted from the results.
If the process is killed, the last persisted Submitting/Planned state is evidence of an uncertain
outcome, not proof of failure or permission to retry blindly.

Files are replaced atomically. They are local records, not tamper-proof external audit storage.
An unwritable audit path stops execution. Disk loss or process termination cannot guarantee a
final outcome record; use the already-persisted journal and independent cloud reads.
Use a short OutDir with Windows PowerShell 5.1 if the environment imposes path-length limits.

Default locations:
- Profile command: %LOCALAPPDATA%/PIM-Automation/cadm-profile/<run-id>/
- Guided command: %LOCALAPPDATA%/PIM-Automation/workflow/<run-id>/

## Expiry updates in plain language

Think of a PIM eligibility as a pass that lets someone ask to use a powerful tool.
The profile is the recipe for making that pass.

If the source pass expires in 30 days, exporting it keeps the same deadline. It does not give
the next person a new 30 days each time you use the profile.

You can edit EndDateTime to choose another fixed deadline. Or remove EndDateTime and use
Duration = 'P90D' to give a newly created eligibility 90 days from assignment, subject to policy.
Do not specify both. SourceEndDateTime is historical information, not the requested deadline.

Changing the recipe does not change passes already issued. Existing eligibility is currently
retained, with its real expiry shown in the evidence. A future explicit renewal feature should
show the old and proposed expiry and require approval before extending access.

## Remaining recommendations

- Broader activation checks: the Azure-resource checks below are implemented. Group/directory
  activation policy, Conditional Access, and approver availability still need separate evaluation.
- Controlled live testing: use a designated test account and a small approved scope before relying
  on production provisioning. Offline tests use pretend cloud responses.
- Partial-failure recovery: if two grants succeed and a third fails, report exactly that.
  A future cleanup tool should remove only grants created by that run, never unrelated access.
- Private backup and review: keep tenant profiles in a protected, versioned location. They remain
  git-ignored in this public-source checkout. Treat changes to a privileged profile like changes
  to a master-key recipe.
- Central audit storage: copy records to a protected destination with retention and access controls
  so the person using the tool cannot quietly erase the history.

## Offline tests

~~~powershell
pwsh -NoProfile -File tests/Invoke-AuditCoverageTests.ps1
powershell -NoProfile -File tests/Invoke-AuditCoverageTests.ps1
python -B -m pytest -q -p no:cacheprovider tests
~~~

Run the existing export, workflow, and P1 safety suites too. On machines that only permit script
execution under working_directory, give pytest a fresh, short --basetemp path inside that checkout.

## Azure activation checks and local backups

Azure-resource profile previews now show MFA, approval, configured approvers, activation
expiration, and maximum activation duration. The check uses ARM reads through the existing Azure
CLI session. It does not request Graph consent, change any Azure policy, or activate access.

By default, the tool reports Azure's existing settings without adding local requirements.
Odyssey and the example tenant use:

~~~powershell
ActivationRequirements = @{}
~~~

Readable settings are labelled Observed, not Pass or Fail. An eight-hour activation limit with
no explicit PIM MFA or approval requirement is reported as configured and does not block the
profile. This does not assert that the settings meet an independently defined security standard.

Operators may explicitly opt into additional local checks by setting RequireMfa, RequireApproval,
or MaximumActivationDuration in ActivationRequirements. Omitted requirements impose no restriction.
These checks never change Azure's policy. Activation duration is distinct from eligibility expiry.

The relevant effective rules are Enablement_EndUser_Assignment, Approval_EndUser_Assignment,
and Expiration_EndUser_Assignment. Admin-assignment and eligibility-duration rules are not
substitutes for these activation rules. Only when RequireApproval is explicitly enabled does the tool require every approval stage to
name a primary user/group approver ID. This confirms configuration only: the tool does not verify that the
approver exists, is available, or is independent of the target user.

Observed means settings were read successfully in report-only mode. Pass means readable rules
meet explicitly configured local requirements. Fail means a readable policy does not meet those
explicit requirements. Unknown means the policy/scope/configuration could not be read or interpreted safely.
Fail and Unknown produce BLOCKED-ACTIVATION-POLICY and prevent apply. A blocked read-only preview
returns exit code 2 and saves its review record. There is no Force bypass for this policy gate.
The grant function rechecks the policy at the write boundary. Any explicitly configured
requirements remain enforced; report-only mode adds no MFA, approval, or duration standard. Policy fingerprints also participate in the post-confirmation stale-plan check.

An authentication-context rule alone is not treated as proof of MFA. Evaluating Conditional
Access needs additional information outside this ARM-only feature. Group and Entra directory-role
activation policies are not checked by this feature. These checks apply to the profile workflows;
the separate clone engine retains its existing policy behavior.

Policy API reference:
[Azure effective role management policy rules](https://learn.microsoft.com/en-us/rest/api/authorization/role-management-policy-assignments/list-for-scope?view=rest-authorization-2020-10-01).

Local backups are stored in scripts/cadm/tenants/<tenant>/backups/<UTC timestamp>-<unique suffix>/.
A snapshot contains byte-for-byte PSD1 copies plus manifest.json with their original paths,
SHA-256 hashes, timestamp, and reason. Comments and encoding are preserved. Existing snapshots
are never overwritten or automatically deleted. All backup folders are git-ignored.

Snapshots are taken automatically for the selected profile before preview/apply/compare, after
creating/exporting a profile, and before a guided template-review edit. The audit record links
the snapshot. A backup failure stops that workflow before grants; on a new-template operation,
the newly created template may remain and the backup error is reported. Manual edits outside the
tool are not watched: run the following offline command first to back up every profile and the
tenant configuration:

~~~powershell
.\scripts\cadm\Backup-CadmProfiles.ps1 -TenantName example
~~~

No Azure login is needed for this command. Local backups protect against mistakes, not malicious
edits, disk loss, or someone deleting the entire working directory. For recovery, review the
manifest and restore the desired PSD1 copy to its recorded source path, then run a preview.
Restoring a file never revokes, extends, or otherwise changes permissions already granted in Azure.

Example read-only live preview from the working_directory checkout:

~~~powershell
.\scripts\cadm\Invoke-CadmAccess.ps1 -Mode profile -ProfileName owner-pim -TargetUser 'target-admin@example.com' -Apply:$false -ConnectGraph:$false
~~~

Profile previews use their exact scopes, with per-scope tenant validation, rather than requiring
an unrelated full subscription refresh. A successful preview checks discovery/planning only;
it does not prove a future grant will succeed.

On 2026-10-29, the local tenant preview resolved the existing admin account but ARM scope
verification encountered Azure CLI's certificate-chain validation error. It recorded Unknown
and blocked the profile. No Azure changes or TLS-verification bypass were performed. This
environmental failure does not establish whether the activation policy meets the standard.

Offline validation:

~~~powershell
pwsh -NoProfile -File tests/Invoke-ActivationBackupTests.ps1
powershell -NoProfile -File tests/Invoke-ActivationBackupTests.ps1
~~~

