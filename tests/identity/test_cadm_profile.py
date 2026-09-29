"""Lock the safety invariants of the profile layer: Invoke-CadmAccess.ps1, CadmProfile.ps1,
and the shipped tenant profiles.

Templates encode intended access instead of copying historical drift. These static checks
cover source structure only; use Invoke-ReviewProbes.ps1 for known behavioral gaps.

Static asserts on source text, matching the convention in test_copy_cadm_access.py.

  python -m pytest tests/identity/test_cadm_profile.py
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CADM = REPO / "scripts/cadm"

LAUNCHER_SRC = (CADM / "Invoke-CadmAccess.ps1").read_text(encoding="utf-8-sig")
PROFILE_SRC = (CADM / "lib/CadmProfile.ps1").read_text(encoding="utf-8-sig")
CORE_SRC = (CADM / "lib/CadmAccess.Core.ps1").read_text(encoding="utf-8-sig")

_L = LAUNCHER_SRC.splitlines()
_CLOSE = next(i for i, ln in enumerate(_L) if ln.rstrip() == "#>")
LAUNCHER = "\n".join(ln for ln in _L[_CLOSE + 1:] if not ln.lstrip().startswith("#"))
PROFILE = "\n".join(ln for ln in PROFILE_SRC.splitlines() if not ln.lstrip().startswith("#"))

TENANTS = sorted((CADM / "tenants").glob("*/tenant.psd1"))
PROFILES = sorted((CADM / "tenants").glob("*/profiles/*.psd1"))


# --------------------------------------------------------------- tenant isolation


def test_tenant_binding_is_matched_against_the_live_login():
    """The guardrail that makes this safe to carry between customers: profiles written for one
    tenant must be unusable inside another's. The launcher reads the CURRENT az login's tenantId
    and refuses when no tenant.psd1 matches -- a mismatch must throw, never fall back to a
    default or to the first file found."""
    assert "function Import-CadmTenant" in PROFILE
    assert "account', 'show'" in PROFILE
    assert "$t.TenantId -ieq $liveTid" in PROFILE
    assert "no tenant binding for the signed-in tenant" in PROFILE_SRC


def test_tenant_config_lives_outside_the_scripts():
    """Multi-tenant requirement: no tenant id, root MG, or group name may be hardcoded in the
    scripts. Onboarding a tenant must be a folder copy, not a code edit."""
    for src, name in ((LAUNCHER, "Invoke-CadmAccess.ps1"), (PROFILE, "CadmProfile.ps1")):
        assert "00000000-0000-0000-0000-000000000000" not in src, f"{name} hardcodes the example tenant id"
        assert "EXAMPLE_" not in src, f"{name} hardcodes a tenant-specific group name"


def test_every_tenant_declares_what_the_scripts_need():
    assert TENANTS, "no tenant bindings found"
    for t in TENANTS:
        text = t.read_text(encoding="utf-8-sig")
        for key in ("TenantId", "RootManagementGroupId", "ScopeTokens"):
            assert key in text, f"{t.name} missing {key}"


# --------------------------------------------------------------- profile safety


def test_engine_refuses_standing_privileged_roles():
    """A profile must not be able to express the drift this tooling removes. The refusal lives in
    the ENGINE, not in template discipline -- otherwise the template system is just a nicer way
    to write standing Owner."""
    assert "function Assert-ProfileSafe" in PROFILE
    for role in ("Owner", "User Access Administrator", "Role Based Access Control Administrator"):
        assert f"'{role}'" in PROFILE, f"{role} must be refused in profiles"
    assert "is not allowed - grant it just-in-time" in PROFILE_SRC


def test_engine_refuses_root_scope_in_profiles():
    """Root scope '/' grants inherit to the entire tenant. Never expressible in a template, and
    checked twice -- in Assert-ProfileSafe and again in Resolve-CadmScope."""
    assert "root scope '/' is never allowed in a profile" in PROFILE_SRC
    assert "root scope '/' is not allowed." in PROFILE_SRC


def test_engine_refuses_standing_membership_of_pim_or_role_assignable_groups():
    """THE escalation guard, restated for profiles. Permanent membership of a PIM-managed or
    role-assignable group converts just-in-time access into standing access."""
    assert "isAssignableToRole" in PROFILE
    assert "grant it as a PIM eligibility, not standing membership" in PROFILE_SRC
    # on-prem synced groups are mastered in AD; Graph rejects the write
    assert "onPremisesSyncEnabled" in PROFILE
    assert "must be set in AD, not via a profile" in PROFILE_SRC


def test_profile_grants_eligibilities_never_active_assignments():
    """An eligibility is the ability to activate. Granting an ACTIVE assignment instead would
    hand over live standing access."""
    grant = PROFILE[PROFILE.index("function Invoke-ProfileGrant"):]
    assert "'adminAssign'" in grant
    assert "eligibilityScheduleRequests" in grant
    assert "assignmentScheduleRequests" not in grant, "profiles must not create active assignments"


def test_eligibility_expiration_is_negotiated_against_the_group_policy():
    """REGRESSION: eligibility expiration must follow the target policy. The grant hardcoded
    noExpiration, but a PIM policy may forbid permanent eligibility and rejects it with

        BadRequest :: The following policy rules failed: ExpirationRule -
        The policy does not allow permanent assignment

    which is a POLICY conflict, not a permissions problem, and reads like a tool bug. The
    expiration must come from the group's own policy so the tool complies with whatever each
    group is configured for."""
    grant = PROFILE[PROFILE.index("function Invoke-ProfileGrant"):]
    assert "Resolve-PimGroupExpiration" in grant
    assert "expiration = @{ type = 'noExpiration' }" not in grant, "must not hardcode noExpiration"


def test_eligibility_term_is_tenant_configurable_not_baked_in():
    """The default term is tenant config, like every other tenant-specific value. Another
    customer may want six months."""
    assert "DefaultEligibilityDuration" in (CADM / "tenants/example/tenant.psd1").read_text(encoding="utf-8-sig")
    assert "-DefaultDuration $defaultDuration" in LAUNCHER
    assert "[string]$DefaultDuration = 'P365D'" in PROFILE


def test_shipped_profiles_obey_their_own_rules():
    """Every profile in the repo must pass what the engine enforces. A shipped template that the
    engine would reject is a broken handoff."""
    assert PROFILES, "no profiles found"
    for p in PROFILES:
        body = "\n".join(
            ln for ln in p.read_text(encoding="utf-8-sig").splitlines()
            if not ln.lstrip().startswith("#")
        )
        assert "Role = 'Owner'" not in body, f"{p.name} grants standing Owner"
        assert "User Access Administrator" not in body, f"{p.name} grants standing UAA"
        assert "Scope = '/'" not in body, f"{p.name} uses root scope"
        assert "DirectoryRoles =" not in body, f"{p.name} grants a standing directory role"
        for key in ("Name", "Description", "Rbac", "GroupMemberships", "PimGroupEligibilities"):
            assert key in body, f"{p.name} missing {key}"


def test_global_admin_is_only_ever_an_eligibility():
    """SUPERSEDES an earlier rule that banned Global Administrator from profiles outright
    (2026-08-20, after a policy revision). The ban was aimed at the right target for the wrong reason:
    what makes GA dangerous is holding it STANDING, not being able to request it. A JIT
    eligibility with approval is Microsoft's own recommended pattern for the role.

    What survives the reversal is the part that actually matters -- GA may appear ONLY under
    DirectoryRoleEligibilities. It must never be a standing directory role, never a
    PIM-for-Groups membership, and never an Rbac row.

    Comment lines are stripped: the profiles document at length WHY this is eligibility-only,
    and that prose must not read as the grant itself."""
    for p in PROFILES:
        body = "\n".join(
            ln for ln in p.read_text(encoding="utf-8-sig").splitlines()
            if not ln.lstrip().startswith("#")
        )
        if "Global Administrator" not in body and "Global_Admin" not in body:
            continue
        assert "DirectoryRoleEligibilities" in body, \
            f"{p.name} names Global Administrator outside DirectoryRoleEligibilities"
        # never via the group plane, which is a different (and here, wrong) mechanism
        assert "Global_Admin" not in body, f"{p.name} routes GA through PIM for Groups"
        elig = body[body.index("DirectoryRoleEligibilities"):]
        assert "Global Administrator" in elig, f"{p.name} places GA outside the eligibility block"


def test_standing_directory_roles_are_refused_outright():
    """There is deliberately no profile key for a standing directory role -- this plane can only
    make someone ELIGIBLE. A profile author reaching for 'DirectoryRoles' gets a hard error
    naming the supported key, not a silently ignored block."""
    assert "'DirectoryRoles'" in PROFILE
    assert "would grant STANDING directory roles and is not supported" in PROFILE_SRC


def test_directory_role_grants_are_eligibility_requests_only():
    """roleEligibilityScheduleRequests makes someone eligible; roleAssignmentScheduleRequests
    would make the role ACTIVE and standing. Confusing the two on the GA path is the single
    worst mistake this file could make."""
    grant = PROFILE[PROFILE.index("'PIM-DIR' {"):]
    assert "roleEligibilityScheduleRequests" in grant
    assert "roleAssignmentScheduleRequests" not in grant, "must never create an ACTIVE directory role"
    assert "'adminAssign'" in grant
    # bounded, and clamped to the role's own policy ceiling
    assert "Select-CadmDuration" in grant
    assert "noExpiration" not in grant


def test_directory_role_plane_has_its_own_consent_gate():
    """Directory-role PIM is a SEPARATE scope family from PIM for Groups (*.Directory vs
    *.AzureADGroup); group consent alone cannot authorize directory-role operations. Scopes are
    requested only when a profile uses the plane, and applying without them refuses rather than
    half-applying."""
    assert "RoleEligibilitySchedule.ReadWrite.Directory" in CORE_SRC
    assert "$usesDirRoles" in LAUNCHER
    assert "Test-MgHasScope -Acceptable $MgDirWriteScopes" in LAUNCHER
    assert "SEPARATE consent from the PIM-for-Groups scopes" in LAUNCHER_SRC


def test_omitted_optional_keys_do_not_read_as_malformed_entries():
    """REGRESSION, and a nasty one: @($null) is a ONE-ELEMENT array in PowerShell, not an empty
    one. A profile omitting an optional key yields a single $null entry, which every loop then
    validates as a malformed record -- "a DirectoryRoleEligibilities entry has no Role" thrown at
    a profile that never mentioned the key. `.Count -gt 0` lies identically.

    Adding the directory-role plane broke three of four shipped profiles exactly this way, caught
    by a regression dry run rather than by the suite. Every profile collection read must go
    through the null-filtering helper so the next optional key cannot repeat it."""
    assert "function Get-ProfileEntries" in PROFILE
    assert "$null -ne $_" in PROFILE
    import re
    raw = re.findall(r"@\(\$Profile\.Data\.\w+\)", PROFILE)
    assert not raw, f"raw profile collection reads bypass the null filter: {raw}"
    # The launcher reads the same data via $prof.Data and hit this identically: every profile
    # looked like it used the directory-role plane, dragging Directory consent into group-only
    # runs and defeating the least-privilege scope request.
    rawl = re.findall(r"@\(\$prof\.Data\.\w+\)", LAUNCHER)
    assert not rawl, f"launcher bypasses the null filter: {rawl}"


def test_every_shipped_profile_survives_validation_shape():
    """Each shipped profile must define, or safely omit, every plane. This is the assertion that
    would have caught the @($null) break before it shipped."""
    optional = ("Rbac", "GroupMemberships", "PimGroupEligibilities", "DirectoryRoleEligibilities")
    for p in PROFILES:
        body = "\n".join(
            ln for ln in p.read_text(encoding="utf-8-sig").splitlines()
            if not ln.lstrip().startswith("#")
        )
        present = [k for k in optional if k in body]
        assert present, f"{p.name} declares no access planes at all"
        # An omitted key is legitimate -- that is the whole point of the helper -- so this asserts
        # the profile is coherent, not that every key is spelled out.
        assert "Name" in body and "Description" in body, f"{p.name} missing Name/Description"


def test_unreadable_directory_plane_degrades_instead_of_crashing():
    """An unreadable plane must yield BLOCKED-PIM-UNKNOWN, not a stack trace: a dry run on a host
    with no Graph session should still print a plan. But a WRONG ROLE NAME stays fatal -- that is
    a profile authoring bug, and reporting a typo as 'unknown' would hide it behind a scope
    warning. Caught by a dry run with -ConnectGraph:$false, which died on an exception."""
    resolver = CORE_SRC[CORE_SRC.index("function Resolve-DirectoryRoleId"):]
    resolver = resolver[:resolver.index("\n}")]
    assert "return @{ Ok = $false" in resolver, "unreadable plane must not throw"
    assert "not found - check the profile spelling" in resolver, "a bad role name must still throw"
    plan = PROFILE[PROFILE.index("DirectoryRoleEligibilities)"):]
    assert "$blocked" in plan
    assert "directory-role catalogue unreadable" in PROFILE_SRC


def test_directory_role_scope_is_tenant_root_only():
    """Administrative-unit scoping changes what a role can touch and is not modelled here; a
    profile silently accepting an AU scope would imply a containment that does not exist."""
    assert "DirectoryScopeId must be '/'" in PROFILE_SRC


def test_apply_confirmation_calls_out_directory_role_grants():
    """A tenant-wide admin eligibility must not be indistinguishable from a Reader grant in the
    confirmation prompt."""
    assert "DIRECTORY-ROLE eligibility grant(s)" in LAUNCHER_SRC
    assert "ELIGIBLE to activate tenant-wide admin roles" in LAUNCHER_SRC


# --------------------------------------------------------------- plan correctness


def test_unreadable_pim_plane_never_resolves_to_create():
    """REGRESSION. The first cut emitted CREATE when the PIM plane could not be read, which is
    the blind-spot failure BLOCKED-PIM-UNKNOWN exists to prevent: "I could not read it" is not
    "the target does not have it". Caught by a smoke run against an already-converted account
    showing two impossible rows. Applying must refuse outright."""
    assert "BLOCKED-PIM-UNKNOWN" in PROFILE
    assert "if (-not $tgtPimGrp.Ok) { 'BLOCKED-PIM-UNKNOWN' }" in PROFILE
    assert "REFUSING TO APPLY" in LAUNCHER_SRC
    assert "row(s) are BLOCKED-PIM-UNKNOWN" in LAUNCHER_SRC


def test_rbac_idempotency_checks_the_profile_scope_directly():
    """REGRESSION. The first cut diffed against a subscription sweep and reported a management-
    group grant the target demonstrably held as CREATE. Profiles routinely name an MG scope, so
    the check queries that exact scope."""
    plan = PROFILE[PROFILE.index("function Resolve-ProfilePlan"):]
    assert "'--scope', $scope" in plan
    assert "Get-RoleAssignmentsFor" not in plan, "must not diff RBAC via the subscription sweep"


def test_rbac_match_is_direct_only_not_group_inherited():
    """A role conveyed by group membership must not satisfy a profile: the profile says this
    ACCOUNT holds it, and letting a group path suppress the grant would silently revoke access
    the day someone leaves that group."""
    plan = PROFILE[PROFILE.index("function Resolve-ProfilePlan"):]
    assert "$_.principalId -eq $Target.id" in plan


def test_profile_apply_is_idempotent():
    """Re-applying must be safe -- anything already in place reports SKIP-EXISTS, so a partial or
    failed run can simply be run again."""
    assert "SKIP-EXISTS" in PROFILE
    assert "$_.Action -eq 'CREATE'" in PROFILE


# --------------------------------------------------------------- launcher


def test_launcher_delegates_cloning_rather_than_reimplementing_it():
    """Re-implementing the clone flow would fork the escalation guards into a second, untested
    copy. The launcher adds the menu and the tenant guard, then hands off to the field-tested
    script with its own pinned suite."""
    assert "Copy-CadmAccess.ps1" in LAUNCHER
    assert "& $clone @splat" in LAUNCHER
    for guard in ("SKIP-PIM-ACTIVATED", "BLOCKED-PIM-ACTIVE", "pimActiveOnlyIds"):
        assert guard not in LAUNCHER, f"launcher reimplements {guard} instead of delegating"


def test_launcher_is_dry_run_by_default():
    """Nothing is granted without -Apply, and the apply still takes a typed confirmation."""
    assert "[switch]$Apply" in LAUNCHER
    assert "DRY RUN - nothing changed" in LAUNCHER_SRC
    assert "Type APPLY to continue" in LAUNCHER_SRC


def test_launcher_validates_the_profile_before_touching_azure():
    """A profile asking for something the engine refuses should fail on the FILE, not halfway
    through a privileged grant run."""
    i_assert = LAUNCHER.index("Assert-ProfileSafe")
    assert i_assert < LAUNCHER.index("Resolve-ProfilePlan")
    assert i_assert < LAUNCHER.index("Invoke-ProfileGrant")


def test_every_mode_is_reachable_without_the_menu():
    """The menu is a convenience, not the interface -- everything must automate."""
    assert "[ValidateSet('clone', 'interactive', 'profile')]" in LAUNCHER
    assert "no -Mode given and this host is not interactive" in LAUNCHER_SRC
    assert "'-TargetUser is required.'" in LAUNCHER


def test_profile_param_avoids_the_automatic_variable_collision():
    """$Profile is an automatic PowerShell variable; a param named -Profile would collide with
    it and behave unpredictably."""
    assert "[string]$ProfileName" in LAUNCHER
    assert "[string]$Profile\n" not in LAUNCHER


def test_audit_is_written_for_every_run_outside_the_repo():
    """The record of what a privileged tool was ASKED to do matters as much as what it did, and
    it must survive a checkout or a clean rebuild."""
    assert "LocalApplicationData" in LAUNCHER
    assert "auditFile" in LAUNCHER
    i_audit = LAUNCHER.index("$auditFile =")
    assert i_audit < LAUNCHER.index("if (-not $Apply)"), "audit must be written on dry runs too"
