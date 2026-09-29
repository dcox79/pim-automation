"""Lock the safety invariants of Copy-CadmAccess.ps1 and its engine.

This tool grants privileged access, so
the guards below are the point of it, not decoration. Static asserts on the source text -- a
live grant is proven by a gated -Apply run, not here.

Since v1.22.0 the code lives in two files: the entry script (help/params/plan/apply flow) and
the dot-sourced engine scripts/cadm/lib/CadmAccess.Core.ps1 (plumbing, discovery, session
logic). SRC/CODE are their union, CORE FIRST -- the ordering asserts below compare positions,
and every engine-vs-engine or flow-vs-flow comparison keeps its old relative order only if the
concatenation order matches the old single-file layout (engine above main flow).

  python -m pytest tests/identity/test_copy_cadm_access.py
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT_SRC = (REPO / "scripts/Copy-CadmAccess.ps1").read_text(encoding="utf-8-sig")
CORE_SRC = (REPO / "scripts/cadm/lib/CadmAccess.Core.ps1").read_text(encoding="utf-8-sig")
SRC = CORE_SRC + "\n" + SCRIPT_SRC

# CODE: the union minus comment lines AND minus the entry script's <# ... #> help block. The
# help survives a naive #-prefix strip, and prose describing a construct reads as the construct
# itself in a "must not appear" assert. BODY is kept as an alias for older tests.
_LINES = SCRIPT_SRC.splitlines()
_CLOSE = next(i for i, ln in enumerate(_LINES) if ln.rstrip() == "#>")
CODE = "\n".join(
    ln
    for ln in (CORE_SRC.splitlines() + _LINES[_CLOSE + 1:])
    if not ln.lstrip().startswith("#")
)
BODY = CODE


# --------------------------------------------------------------- privilege guards


def test_root_scope_excluded_by_default():
    """User Access Administrator at '/' lets the holder grant any role anywhere in the tenant,
    including to themselves. It must never ride along silently."""
    assert "EXCLUDED-ROOT" in CODE
    assert "-not $AllowRootScope" in CODE


def test_pim_managed_groups_are_not_cloned_as_permanent_members():
    """THE escalation guard. An ACTIVATED PIM-for-Groups eligibility appears in /memberOf
    identically to a standing membership; cloning it naively grants the target permanent
    membership where the source only holds activate-on-demand access, and escapes the PIM
    audit trail."""
    assert "SKIP-PIM-MANAGED" in CODE
    assert "$pimEligibleGroupIds" in CODE
    # both a standing eligibility AND a currently-activated one must feed the exclusion set
    assert "$srcPimGrp.ActiveGroupIds" in CODE


def test_group_derived_rbac_is_never_recreated_directly():
    """Recreating a group-inherited assignment as a direct user assignment would grant the same
    access on a path that survives removal from the group."""
    assert "INFO-VIA-GROUP" in CODE
    assert "$r.principalType -eq 'Group'" in CODE


def test_onprem_groups_emit_ad_actions_rather_than_failing():
    assert "BLOCKED-ONPREM" in CODE
    assert "Add-ADGroupMember" in CODE


def test_disabled_target_is_refused():
    assert "-not $tgt.accountEnabled" in CODE


def test_source_and_target_must_differ():
    assert "$src.id -eq $tgt.id" in CODE


# --------------------------------------------------------------- apply preflight


def test_unreadable_pim_plane_blocks_permanent_group_grants():
    """An activated PIM-for-Groups eligibility is INDISTINGUISHABLE from a standing membership
    in /memberOf. With the PIM plane unreadable, treating a group as 'not PIM-managed' would
    grant permanent access the source only holds on demand -- the exact escalation
    SKIP-PIM-MANAGED exists to prevent, reachable any time Graph is not connected."""
    assert "BLOCKED-PIM-UNKNOWN" in CODE
    assert "if (-not $srcPimGrp.Ok)" in CODE
    # must block, not fall through to a CREATE
    block_at = CODE.index("BLOCKED-PIM-UNKNOWN")
    create_at = CODE.index("Plane='GROUP'; Action='CREATE'")
    assert block_at < create_at, "the unreadable-plane guard must precede the CREATE path"


def test_runs_on_both_powershell_editions():
    """An operator may run pwsh 7 but operators may only have Windows PowerShell 5.1 (e.g. an RSAT box
    for the on-prem half). Verified running identically on 5.1 and 7.x."""
    assert SRC.splitlines()[0].strip() == "#requires -Version 5.1"
    for ps7_only in ("-SkipHttpErrorCheck", "ForEach-Object -Parallel", "??", "Join-String"):
        assert ps7_only not in BODY, f"{ps7_only} is PowerShell 7 only"


def test_apply_refuses_without_pim_group_write_scope():
    """Without this, -Apply lands the RBAC and group grants and fails every PIM-for-Groups
    write -- a partial clone that looks finished. Must refuse BEFORE creating anything."""
    assert "REFUSING TO APPLY" in SRC
    assert "Test-MgHasScope -Acceptable $MgWriteScopes" in CODE
    assert "exit 2" in CODE
    # the refusal has to precede the create loop, or it is not a preflight
    assert SRC.index("REFUSING TO APPLY") < SRC.index("foreach ($item in $todo)")


def test_readwrite_scopes_satisfy_the_read_requirement():
    """ReadWrite implies Read; a session connected with write scopes must not be reported as
    unable to read."""
    assert "$MgReadScopes" in CODE
    for s in ("PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
              "PrivilegedAccess.ReadWrite.AzureADGroup"):
        read_block = CODE[CODE.index("$MgReadScopes"):CODE.index("$MgWriteScopes")]
        assert s in read_block, f"{s} must also satisfy the read check"


def test_readonly_session_warns_during_dry_run():
    """Finding out at apply time is too late -- the dry run is where this belongs."""
    assert "PIM FOR GROUPS - READ-ONLY SESSION" in SRC


def test_unreadable_plane_is_not_reported_as_none():
    """An unread plane must never imply parity."""
    assert "PIM FOR GROUPS - UNREADABLE" in SRC
    assert 'not the same as "none"' in SRC


# --------------------------------------------------------------- windows az plumbing


def test_az_invoked_via_python_entry_point_not_the_cmd_shim():
    """az.cmd re-invokes python without re-quoting, so cmd.exe eats '(' ')' in OData filters
    and splits URLs at '&'. Percent-encoding fixes only the parens."""
    assert "Initialize-AzInvoker" in CODE
    assert "-IBm" in CODE and "azure.cli" in CODE
    # the superseded workaround must not creep back in
    assert "%28" not in CODE and "%29" not in CODE


def test_role_definition_id_normalised_to_guid():
    """ARM prefixes roleDefinitionId with whichever subscription was queried, so one
    root/MG-scoped assignment yields a distinct key per subscription -- 23 duplicate rows, and
    a target-exists check that silently misses."""
    assert "function Get-RoleDefGuid" in CODE
    assert "Get-RoleDefGuid $r.roleDefinitionId" in CODE


def test_audit_output_defaults_outside_the_repo():
    """Audit output written inside a working tree leaves untracked files behind and can be
    discarded by a clean checkout or rebuild -- losing the only record of a privileged grant."""
    assert "GetFolderPath('LocalApplicationData')" in CODE
    assert "PIM-Automation/cadm-clone/" in CODE
    assert "audit/rbac-clone" not in CODE, "default OutDir must not be repo-relative"


def test_comment_based_help_actually_binds():
    """Get-Help binds a script's help block only under strict whitespace rules, and when they
    are broken it does not warn -- it silently returns the auto-generated syntax, so the whole
    QUICK START becomes invisible to anyone who does not open the file. All three rules were
    violated at some point while writing this script; each is checked here.

    Structural check rather than invoking pwsh, so it runs anywhere. Reads the ENTRY SCRIPT
    alone: the whitespace rules bind the file Get-Help is pointed at, and the dot-sourced core
    carries no help block.
    """
    lines = SCRIPT_SRC.splitlines()

    # Rule 1: exactly one blank line between #requires and the opening marker, no comments.
    assert lines[0].startswith("#requires"), "requires must be the first line"
    assert lines[1].strip() == "", "a blank line must follow #requires"
    assert lines[2].startswith("<#"), (
        "the help block must open immediately after that blank line -- a comment line here "
        "silently breaks the binding"
    )

    # Rule 2: at least two blank lines between the closing marker and the first code line.
    close = next(i for i, ln in enumerate(lines) if ln.rstrip() == "#>")
    after = lines[close + 1:]
    first_code = next(i for i, ln in enumerate(after) if ln.strip() and not ln.lstrip().startswith("#"))
    blanks = [ln for ln in after[:first_code] if not ln.strip()]
    assert len(blanks) >= 2, f"need >=2 blank lines after the help block, found {len(blanks)}"

    # Rule 3: the closing marker must not appear inside the block -- it terminates it early
    # and the rest of the help is then parsed as code (a real parse failure, not just lost help).
    body = "\n".join(lines[2:close])
    assert "#>" not in body, "closing comment marker inside the help block ends it early"


def test_quick_start_documents_the_full_sequence():
    """Whoever runs this has no other instructions to go on."""
    assert "QUICK START" in SRC
    for step in ("-Apply", "ad-actions-", "pimGroupsReadable", "ConnectGraph"):
        assert step in SRC, f"quick start must cover {step}"
    # exit codes matter for anyone wrapping this in a pipeline
    assert "Exit codes:" in SRC


def test_graph_autoconnect_is_on_by_default():
    """The not-connected path is the one mistake that quietly degrades a run, so connecting is
    the default. A [switch] cannot default to true -- it has to be a [bool]."""
    assert "[bool]$ConnectGraph = $true" in CODE
    assert "function Connect-GraphIfNeeded" in CODE
    assert "Connect-GraphIfNeeded" in CODE.split("function Connect-GraphIfNeeded")[1], \
        "the function must actually be called, not just defined"


def test_autoconnect_reconnects_an_unusable_session():
    """A session that cannot actually read the plane otherwise sails through the dry run and
    -Apply refuses at the last moment. Requesting write scopes up front makes one connection
    serve both. The trigger is now a failed PROBE rather than a scope-list comparison -- the
    list could echo the request, so it accepted sessions that did not work."""
    assert "Test-MgPlaneUsable -PrincipalId $ProbePrincipalId" in CODE
    assert "$scopeSets.Add(@($MgScopeList))" in CODE
    assert "$MgScopeList + $MgWriteScopeList" in CODE
    assert "Reconnecting." in SRC
    assert "Retrying with the broader scope set" in SRC


def test_device_code_signin_supported_for_vdi():
    """VDI / locked-down desktops often have no usable default browser, so the interactive
    redirect never completes. The device-code switch is spelled differently across Graph SDK
    builds -- 2.36.1 exposes -UseDeviceCode and lacks -UseDeviceAuthentication entirely --
    so the script probes for each rather than assuming a version mapping."""
    assert "[switch]$UseDeviceCode" in CODE
    assert "ContainsKey('UseDeviceCode')" in CODE
    assert "ContainsKey('UseDeviceAuthentication')" in CODE


def test_browser_failure_recovers_without_operator_action():
    """Superseded telling the user to re-run with a flag: the script now retries with a device
    code itself. An operator should not need to know the flag exists to get past a VDI."""
    assert "retrying with a device code" in SRC


def test_missing_module_hint_needs_no_admin():
    """VDI users rarely have admin; a bare Install-Module would fail."""
    assert "Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" in SRC


def test_pim_directory_role_checked_early():
    """Delegated access is scope AND role. Consented scopes do not grant PIM-for-Groups writes
    on their own, and the usual miss is forgetting to ACTIVATE an eligible role in PIM before
    connecting -- which otherwise surfaces only at -Apply, after a full scan."""
    assert "function Get-MgPimRoleStatus" in CODE
    assert "Privileged Role Administrator" in CODE
    assert "not ACTIVATED in PIM before connecting" in SRC
    # the role is minted into the token at sign-in, so an existing session must be dropped
    assert "Disconnect-MgGraph" in SRC


def test_unknown_role_status_does_not_block_apply():
    """The role lookup can itself be denied. Treating 'unknown' as 'missing' would block a
    legitimate apply on a failed read -- worse than letting Graph return the real error."""
    assert "$pimRoleStatus -eq 'missing'" in CODE
    assert "$pimRoleStatus -ne 'unknown'" not in CODE
    assert "'unknown' is deliberately allowed" in SRC


def test_no_multi_repo_references():
    """This script is maintained in one repo; references to a second one are stale framing."""
    for term in ("legacy-network-repo", "legacy-build-repo", "either repo", "both repos"):
        assert term not in SRC, f"stale multi-repo reference: {term}"


def test_autoconnect_never_hangs_an_unattended_host():
    """An interactive sign-in on a non-interactive host would block forever."""
    assert "[Environment]::UserInteractive" in CODE
    assert "-ConnectGraph" in SRC


def test_target_comparison_key_omits_principal_id():
    """Source and target ARE different principals; including principalId in the comparison key
    would make every SKIP-EXISTS check fail and re-grant everything."""
    assert "$tgtRaKeys" in CODE


def test_activated_pim_elevation_not_cloned_as_permanent_rbac():
    """The worst escalation in this tool. `az role assignment list` cannot distinguish a
    CURRENTLY ACTIVATED PIM elevation from a standing grant -- an activation materialises as an
    ordinary roleAssignment for its lifetime. Cloning an operator who happens to be elevated
    would convert their temporary elevation into PERMANENT access for the target.

    Observed live 2026-08-17: Owner at Tenant Root Group, assignmentType=Activated, twelve
    hours from expiry, planned as a permanent CREATE. assignmentType is the discriminator."""
    assert "function Get-PimActivatedFor" in CODE
    assert "$p.assignmentType -notin @('Activated', 'Assigned')" in CODE
    assert "Get-CadmField $p 'endDateTime'" in CODE
    assert "SKIP-PIM-ACTIVATED" in CODE
    # must be checked before the CREATE path, or it never fires
    assert CODE.index("SKIP-PIM-ACTIVATED") < CODE.index("$tgtRaKeys.ContainsKey($cmp)")


def test_rbac_blocked_when_activation_state_unknown():
    """-SkipPim or a denied read means an activation cannot be told from a standing grant.
    Refuse rather than silently promote someone's elevation into a permanent grant."""
    assert "$SkipPim -or $srcActivated.Denied" in CODE


def test_scopes_requested_match_what_the_run_needs():
    """A dry run reads; only -Apply writes. Requesting write scopes for a report-only run forces
    every reporting user to hold PIM-for-Groups WRITE consent they never exercise, and blocks
    accounts that legitimately only have read -- which decides who can run the tool at all."""
    assert "$MgReadScopeList" in CODE and "$MgWriteScopeList" in CODE
    assert "$MgScopeList = if ($Apply) { $MgWriteScopeList } else { $MgReadScopeList }" in CODE
    # the read set must not smuggle in a write scope
    read_block = CODE[CODE.index("$MgReadScopeList"):CODE.index("$MgWriteScopeList")]
    assert "ReadWrite" not in read_block


def test_readonly_warning_only_when_applying():
    """A dry run connects read-only on purpose, so warning about it would fire every time."""
    assert "if ($Apply -and -not $SkipGroups -and $srcPimGrp.Ok" in CODE


def test_subscription_list_is_refreshed():
    """The az CLI snapshots the subscription list at login and never refreshes it, so the same
    identity can see different inventories on different machines. This script scans only what az hands it, so a stale cache yields a plan that
    looks complete while missing every grant in the subscriptions it never examined."""
    assert "'account', 'list', '--refresh', '--all'" in CODE
    # a failed refresh must degrade loudly, not silently fall back to a stale list
    assert "could not refresh subscriptions" in SRC


def test_signin_falls_back_to_device_code_automatically():
    """Requiring an operator to know about -UseDeviceCode turns a normal VDI into a support
    call. Browser first, device code on failure, without being asked."""
    assert "$attempts = if ($UseDeviceCode) { @($true) } else { @($false, $true) }" in CODE
    assert "retrying with a device code" in SRC


def test_handoff_runbook_exists_and_covers_the_dangerous_rows():
    """Handed to other people, so the PIM rows must be explained where they will be read."""
    doc = (REPO / "handoff/copy-cadm-access.md").read_text(encoding="utf-8")
    for term in ("SKIP-PIM-ACTIVATED", "BLOCKED-PIM-UNKNOWN", "pimGroupsReadable",
                 "-UseDeviceCode", "ad-actions-"):
        assert term in doc, f"runbook must cover {term}"
    assert "Never grant this" in doc


def test_connect_verifies_the_session_with_a_real_call():
    """Connect-MgGraph does NOT fail when a requested scope is unconsented -- it connects with
    whatever it could get, so the session reports healthy and then 403s on first use. Observed:
    a dry run asked for the .Read scopes, the tenant consents only the .ReadWrite pair, and the
    run printed 'connected as ...' followed by 'Forbidden'.

    Verification must therefore be a real call. Checking the reported scope list instead is what
    let that session pass -- see test_existing_graph_session_is_probed_not_trusted."""
    assert "Test-MgPlaneUsable -PrincipalId $ProbePrincipalId" in CODE
    assert "PIM eligibility or policy-read permission is still unavailable" in SRC
    # The real Graph error must surface, not just a bare status.
    assert "probe: $($script:MgProbeError)" in CODE


def test_connect_falls_back_to_the_broader_scope_set():
    """Least privilege first, but a tenant that only consents ReadWrite must still work."""
    assert "$scopeSets.Add(@($MgScopeList))" in CODE
    assert "$MgScopeList + $MgWriteScopeList" in CODE
    assert "Retrying with the broader scope set" in SRC


def test_scan_shows_progress():
    """Five sweeps x ~5 az calls per subscription is minutes of silence on a 23-sub tenant. It
    reads as a hang -- the run was killed and restarted twice before anyone realised it was just
    working. A dot per subscription shows life and stays readable in a captured log."""
    assert "function Start-Phase" in CODE and "function Step-Phase" in CODE
    assert "roughly $([int]($subs.Count * 5 * 2.5 / 60)) min" in CODE


def test_device_code_output_is_not_swallowed():
    """The device-code flow prints its URL and one-time code through the output stream. Piping
    Connect-MgGraph to Out-Null suppressed the stream and therefore the code itself: the user
    saw 'a URL and code will be printed below', no code ever appeared, and the sign-in died
    120s later on an inactivity timeout. Same swallowed-output trap as $script:MailSent."""
    assert "Connect-MgGraph @p | Out-Null" not in CODE
    assert "$null = Connect-MgGraph" not in CODE
    assert "Connect-MgGraph @p" in CODE


def test_forbidden_names_the_stale_token_cause():
    """Connected, right scopes, still Forbidden: a Graph token carries the roles held AT
    SIGN-IN, so a session opened before a PIM activation (or one whose activation lapsed) is
    refused while looking perfectly healthy. The message must name Disconnect-MgGraph."""
    assert "$srcPimGrp.Error -match 'Forbidden|Authorization'" in CODE
    assert "Disconnect-MgGraph" in SRC
    assert "carries the roles you held when it was" in SRC


def test_global_administrator_does_not_cover_the_reads():
    """Per "List eligibilityScheduleInstances", the supported roles are Global Reader or
    Privileged Role Administrator (role-assignable groups), or Global Reader / Directory Writer /
    Groups Administrator / Identity Governance Administrator / User Administrator
    (non-role-assignable). Global Administrator is on neither list.

    Proven live, twice, one variable apart: a Global-Administrator-only account is refused 403 on
    a cross-principal read with a fresh sign-in and both scope sets consented, while an account
    holding Global Reader + Global Administrator succeeds.

    v1.13 briefly added GA to the READ list on the strength of a different doc -- the PIM
    Permissions section naming "Privileged Role Administrator or Global Administrator" for
    groupsAssignableToRoles/members/update, which governs membership MANAGEMENT, not these
    schedule reads. Do not merge the two lists again."""
    role_block = CODE[CODE.index("$PimGroupReadRoles"):CODE.index("function ")]
    read_block = role_block[:role_block.index("$PimGroupWriteRoles")]
    assert "'Global Administrator'" not in read_block
    assert "'Global Reader'" in read_block
    assert "'Privileged Role Administrator'" in read_block
    # Retained for writes: documented for membership management and not disproved, and this file
    # refuses only on what it can prove.
    write_block = role_block[role_block.index("$PimGroupWriteRoles"):]
    assert "'Global Administrator'" in write_block


def test_interactive_mode_implies_apply_and_the_widest_candidate_set():
    """-Interactive is an APPLY mode by definition -- the selection IS what gets granted -- and it
    widens candidates to everything duplicable: root-scope rows and PIM-ACTIVE promotions are
    shown labeled instead of pre-excluded, because a human picking rows one by one IS the
    deliberate decision those exclusions exist to force."""
    assert "[switch]$Interactive" in CODE
    blk = CODE[CODE.index("if ($Interactive) {"):]
    blk = blk[:blk.index("$MgScopeList")]
    assert "$Apply = $true" in blk
    assert "$AllowRootScope = $true" in blk
    assert "$IncludePimActive = $true" in blk
    # Prompting needs a human; unattended hosts must be refused, not hung.
    assert "[Environment]::UserInteractive" in blk


def test_interactive_selection_runs_before_the_apply_preflights():
    """The preflights gate on what will actually be granted, so an operator who deselects every
    PIM-GRP row must not be refused for lacking a PIM write role they no longer need."""
    sel = CODE.index("INTERACTIVE - select what to clone")
    assert CODE.index("$todo = @($plan | Where-Object") < sel
    assert sel < CODE.index("$pimGrpTodo = @($todo")


def test_interactive_menu_is_numbered_cancellable_and_flags_root_scope():
    """Comma-separated numbers, 'all', blank cancels with no changes, invalid input re-prompts
    rather than aborting or (worse) proceeding, and a root-scope row is impossible to mistake for
    an ordinary one."""
    assert "comma-separated, e.g. 1,4,7" in SRC
    assert "'all'" in SRC
    assert "Nothing selected - exiting with no changes." in SRC
    assert "ROOT SCOPE - inherits to the ENTIRE tenant" in SRC
    # invalid tokens loop back (continue), and duplicates collapse
    menu = CODE[CODE.index("INTERACTIVE - select what to clone"):]
    menu = menu[:menu.index("Selected {0} grant(s)")]
    assert "continue" in menu
    assert "Sort-Object -Unique" in menu


def test_not_cloned_section_lists_every_gap_with_a_remedy():
    """The plan table lists actions; an operator afterwards asks 'what did I NOT get, and what do
    I do now?'. Without this section the blocked rows are scattered through a 25-line table sorted
    by plane and the remedy for each lives only in the runbook. Every blocked/excluded action must
    carry a remedy line."""
    assert "NOT CLONED" in SRC
    for action in ("BLOCKED-ONPREM", "BLOCKED-PIM-ACTIVE", "BLOCKED-PIM-UNKNOWN",
                   "EXCLUDED-ROOT", "SKIP-PIM-ACTIVATED"):
        assert f"'{action}'" in CODE, f"{action} needs a NOT CLONED remedy"
    # The second-step command must be copy-pasteable, carrying -Apply only when applying.
    assert "-IncludePimActive$extra" in CODE


def test_include_pim_active_grants_eligibility_not_standing_access():
    """BLOCKED-PIM-ACTIVE means the source holds the group via a PIM ACTIVE assignment with no
    eligibility behind it. Cloning it as permanent membership would convert the source's on-demand
    access into the target's STANDING access -- the exact escalation this plane exists to stop. The
    opt-in therefore grants an ELIGIBILITY: the ability to activate, without standing access.

    It must also carry no expiry. The source's active assignment is time-bound and often hours from
    lapsing, so copying its end date would mint an eligibility that expires almost immediately."""
    assert "[switch]$IncludePimActive" in CODE
    assert "granted as an ELIGIBILITY, not standing access" in SRC
    assert "Plane='PIM-GRP'; Action=$(if ($tgtPimGrp.Ok) { 'CREATE' } else { 'BLOCKED-PIM-UNKNOWN' })" in CODE
    # accessId must be carried, not guessed: member vs owner is not inferable.
    assert "$srcPimGrp.ActiveMap[$g.id]" in CODE
    assert "ActiveMap = $active" in CODE


def test_pim_group_expiration_respects_the_group_policy():
    """REGRESSION, found live 2026-08-19. A PIM policy may forbid permanent eligibility and
    rejects a noExpiration request with 'ExpirationRule - The policy does not allow permanent
    assignment'. Promoted rows (-IncludePimActive) have no source expiry to mirror, so they must
    fall through to the group's policy rather than assuming permanent.

    The reader must not confuse the two rules: Expiration_Admin_Eligibility governs how long an
    admin-assigned ELIGIBILITY may last, which is not the activation duration."""
    assert "function Get-PimGroupExpirationRule" in CODE
    assert "function Resolve-PimGroupExpiration" in CODE
    assert "'Expiration_Admin_Eligibility'" in CODE
    # Never permanent. Any policy forbidding permanent assignment refuses it, and an eligibility
    # that lapses is the safer failure than one that accumulates silently.
    resolve = CODE[CODE.index("function Resolve-PimGroupExpiration"):]
    resolve = resolve[:resolve.index("\n}")]
    assert "'noExpiration'" not in resolve, "eligibilities must never default to permanent"
    assert "P365D" in resolve
    # Clamping is as load-bearing as reading the policy: a year sent at a group capped lower
    # fails with a DIFFERENT ExpirationRule error, trading one BadRequest for another. It lives
    # in Select-CadmDuration so the group and directory-role planes cannot drift apart.
    assert "Select-CadmDuration" in resolve
    clamp = CODE[CODE.index("function Select-CadmDuration"):]
    clamp = clamp[:clamp.index("\n}")]
    assert "$defTs -gt $maxTs" in clamp
    assert "function ConvertTo-CadmTimeSpan" in CODE
    grp = CODE[CODE.index("'PIM-GRP' {"):]
    assert "Resolve-PimGroupExpiration" in grp[:1200]
    # policy reads are Graph-only; the az first-party app lacks RoleManagementPolicy.Read
    rule_fn = CODE[CODE.index("function Get-PimGroupExpirationRule"):]
    assert "Invoke-MgJson" in rule_fn[:1600]


def test_promoted_rows_survive_the_apply_lookup():
    """A promoted row is NOT in $srcPimGrp.Map -- that map holds eligibilities only -- so the
    apply-time lookup returns $null for it. Without the row carrying its own AccessId the grant
    would throw on a null reference."""
    assert "$item.PSObject.Properties['AccessId']" in CODE
    assert "$e = if ($srcKey) { $srcPimGrp.Map[$srcKey] } else { $null }" in CODE
    # groupId must come from the row, not the (possibly null) map entry.
    assert "groupId      = $item.Scope" in CODE


def test_pim_falls_back_to_per_group_queries():
    """The two query shapes do NOT carry the same authorization. `$filter=principalId eq ...` is a
    directory-wide sweep; `$filter=groupId eq ...` is the documented administrator path. Proven
    live: an account holding Global Reader AND Global Administrator, fresh token, PIM scopes
    consented, is refused 'Attempted to perform an unauthorized operation' on by-principal and
    succeeds on by-group against the same tenant seconds apart.

    By-principal is still tried first -- one call, and it works for a caller who does hold the
    directory-wide permission -- with the per-group fan-out only on refusal."""
    fn = CODE[CODE.index("function Get-PimGroupsFor"):CODE.index("function Get-GroupsFor")]
    assert "principalId eq '$PrincipalId'" in fn      # cheap path first
    assert "groupId eq '$gid'" in fn                  # fallback
    # By-group returns EVERY principal on the group, so the caller must be filtered out.
    assert "[string]$e.principalId -ne $PrincipalId" in fn
    assert "[string]$a.principalId -ne $PrincipalId" in fn


def test_pim_group_candidates_are_not_memberof_alone():
    """A PIM-*eligible* member is not a member until they activate, so /memberOf omits exactly the
    eligibilities this plane exists to find. Role-assignable groups must be in the candidate set.

    There is NO API listing PIM-onboarded groups: roleManagementPolicies requires BOTH scopeId and
    scopeType, and scopeId must name one group -- enumerating with `?$filter=scopeType eq 'Group'`
    returns "BadRequest :: The required parameters ScopeId is missing". Do not reintroduce it."""
    fn = CODE[CODE.index("function Get-PimCandidateGroupIds"):CODE.index("function Get-PimGroupsFor")]
    assert "isAssignableToRole eq true" in fn
    assert "memberOf/microsoft.graph.group" in fn
    # The banned shape is the ENUMERATION: a scopeType filter with no scopeId. Filtering by
    # scopeType alongside a specific scopeId is correct and is how the expiration-policy read
    # works, so this cannot be a blanket ban on the token.
    assert "scopeType eq 'Group'" not in fn, "candidate enumeration must not use the policy filter"
    for ln in CODE.splitlines():
        if "scopeType eq 'Group'" in ln:
            assert "scopeId eq" in ln, f"scopeType filter without scopeId (returns BadRequest): {ln.strip()}"
    # Dynamic and on-prem-synced groups cannot be PIM-managed - querying them is throttle risk.
    assert "DynamicMembership" in fn
    assert "onPremisesSyncEnabled" in fn
    assert "$script:PimManagedGroupIds" in fn


def test_empty_group_list_is_wrapped_at_the_call_site():
    """`return @()` from a PowerShell function unrolls to nothing, so an empty result arrives as
    $null and $groupIds.Count throws "The property 'Count' cannot be found on this object" --
    which crashed the run after the plan had already been computed."""
    assert "@(Get-PimCandidateGroupIds -PrincipalId $PrincipalId)" in CODE


def test_partial_per_group_sweep_is_not_reported_as_success():
    """Silently dropping unreadable groups would under-report eligibilities, and an under-reported
    PIM plane is precisely what BLOCKED-PIM-UNKNOWN exists to prevent. A partial sweep must fail
    loudly and name how many groups were missed."""
    fn = CODE[CODE.index("function Get-PimGroupsFor"):CODE.index("function Get-GroupsFor")]
    assert "per-group fallback incomplete" in fn
    assert "group(s) unreadable" in fn


def test_pagination_is_followed_where_a_short_list_would_be_wrong():
    """Invoke-MgJson returns one page. A truncated PIM-managed-group list means a missing
    eligibility in a plan that still looks complete."""
    assert "function Invoke-MgJsonAll" in CODE
    assert "@odata.nextLink" in CODE
    fn = CODE[CODE.index("function Get-PimGroupsFor"):CODE.index("function Get-GroupsFor")]
    assert "Invoke-MgJsonAll" in fn


def test_probe_accepts_a_session_that_can_only_do_per_group():
    """Global Reader covers by-group but not the by-principal sweep, so a session failing the
    cheap probe can still complete the whole job. Failing outright would send a perfectly capable
    operator away with BLOCKED-PIM-UNKNOWN."""
    fn = CODE[CODE.index("function Test-MgPlaneUsable"):CODE.index("function Invoke-MgJson")]
    assert "groupId eq '$gid'" in fn
    assert "by-group:" in fn


def test_scope_set_retry_compares_by_index_not_by_value():
    """PowerShell's -ne between two ARRAYS filters rather than returning a boolean: it yields the
    left-hand elements not equal to the right operand, a non-empty collection, which is always
    truthy. `if ($scopeSet -ne $scopeSets[-1])` therefore never held, so the session was
    disconnected even after the FINAL attempt -- destroying the graph roles/scopes diagnostics and
    leaving UNREADABLE with no session to describe. Observed as two 'Failed to clear the persisted
    MSAL token cache' warnings on a run with exactly two scope sets."""
    assert "$scopeSet -ne $scopeSets[-1]" not in CODE
    assert "$si -lt ($scopeSets.Count - 1)" in CODE
    assert "for ($si = 0; $si -lt $scopeSets.Count; $si++)" in CODE


def test_graph_error_leads_with_the_json_body_not_the_headers():
    """The raw error text starts with the HTTP status line and a wall of response headers, so a
    blind truncation spends its budget on Transfer-Encoding / Vary / request-id and discards the
    JSON body. That is how a 'PermissionScopeNotGranted' stayed unread behind 'Forbidden ...
    x-ms-...' through several rounds of wrong diagnosis. errorCode and the human message must be
    extracted and put first."""
    assert "errorCode" in CODE
    fn = CODE[CODE.index("function Invoke-MgJson"):]
    fn = fn[:fn.index("\n}")]
    assert "[regex]::Match" in fn
    # Brace exclusion: the OUTER message value is itself nested JSON, so it must be skipped in
    # favour of the inner actionable sentence.
    assert "[^\"\\\\{}]" in fn


def test_failed_probe_does_not_destroy_the_session():
    """v1.14 disconnected on a failed probe. When every reconnect also failed the run ended with
    no session: Test-MgConnected went false, the `graph roles:` / `graph scopes:` lines were
    skipped, and UNREADABLE reported 'no Get-MgContext session' instead of the real 403 -- the
    change that added the diagnostics destroyed them. Keep the session so the failure is still
    describable."""
    connect_fn = CODE[CODE.index("function Connect-GraphIfNeeded"):CODE.index("function Get-MgPimRoleStatus")]
    probe_fail = connect_fn[connect_fn.index("cannot read PIM for Groups"):]
    # Only the between-scope-set retry may disconnect, and that is guarded and comes later.
    assert "Disconnect-MgGraph" not in probe_fail[:400]
    # UNREADABLE must prefer a real error over "no session".
    assert "no error was captured" in SRC


def test_unreadable_section_names_the_wam_token_cache():
    """Directory says the role and consent are present, the call still 403s: Windows brokers the
    sign-in through WAM, whose cache survives Disconnect-MgGraph, so a newly added role or newly
    consented scope may never reach the token. -UseDeviceCode bypasses the broker."""
    assert "WAM" in SRC
    assert "survives Disconnect-MgGraph" in SRC
    assert "-UseDeviceCode, which bypasses the broker" in SRC


def test_read_refusal_names_global_reader_as_the_fix():
    """The failure mode is a break-glass GA account that looks fully privileged and is refused
    anyway. Naming the specific missing role turns that into a one-line fix instead of a hunt."""
    assert "Global Administrator does NOT qualify - Global Reader does" in SRC


def test_existing_graph_session_is_probed_not_trusted():
    """An existing session must be validated with a REAL call, never by reading back
    (Get-MgContext).Scopes. On several SDK builds that property echoes the scopes requested at
    Connect-MgGraph rather than the ones granted, so a hand-rolled `Connect-MgGraph -Scopes
    ...Read...` in a tenant that only consents .ReadWrite reported healthy and then 403'd on
    every call -- and, because it was accepted, skipped the broader-scope retry written for
    exactly that tenant. The operator's own connect defeated the workaround."""
    assert "function Test-MgPlaneUsable" in CODE
    assert "Test-MgPlaneUsable -PrincipalId $ProbePrincipalId" in CODE
    # Reported scopes may require reconnect, but never replace the real eligibility probe.
    connect_fn = CODE[CODE.index("function Connect-GraphIfNeeded"):CODE.index("function Get-MgPimRoleStatus")]
    assert "Test-MgHasScope -Acceptable $policyReadScopes" in connect_fn
    assert "$policyScopeOk -and (Test-MgPlaneUsable -PrincipalId $ProbePrincipalId)" in connect_fn
    # A session that fails the probe must be dropped; scopes cannot be added in place.
    assert "Disconnect-MgGraph" in connect_fn


def test_probe_uses_the_source_principal_not_the_signed_in_user():
    """Any user may read their OWN PIM eligibilities with no admin role and no PIM scope -- that
    is how PIM end-users see what they can activate. A self-probe therefore returns 200 for
    everybody and proves nothing. Confirmed live: a GA session read its own schedules fine while
    403ing on the source principal's. The probe must use the principal actually being read."""
    assert "Connect-GraphIfNeeded -ProbePrincipalId $src.id" in CODE
    probe_fn = CODE[CODE.index("function Test-MgPlaneUsable"):]
    assert "$PrincipalId" in probe_fn[:600]
    assert "principalId eq '$PrincipalId'" in probe_fn


def test_both_auth_gates_are_printed_on_every_run():
    """Delegated access is scope AND role. A bare 403 names neither, so both must appear in the
    normal banner -- not only inside a failure branch, where a dry run never reaches them.
    Diagnosing this cost three round-trips before the lines existed. The scope line must be
    labelled as requested-not-granted so nobody reads it as proof."""
    assert "graph roles:" in SRC
    assert "graph scopes:" in SRC
    assert "not proof of grant" in SRC
    # Printed before the 'missing' branch, i.e. unconditionally for a connected session.
    assert CODE.index('"  graph roles:  "') < CODE.index("$pimRoleStatus -eq 'missing'")


def test_pim_role_check_has_an_escape_hatch_for_group_owners():
    """An ACTIVE OWNER of a group can write its PIM assignments holding no directory role at
    all, and the preflight cannot see ownership. Without a bypass the tool would refuse a
    legitimate owner -- the same class of false-negative as the Global Administrator bug.
    -SkipPimRoleCheck relaxes the ROLE gate only; the scope gate still applies."""
    assert "[switch]$SkipPimRoleCheck" in CODE
    assert "$pimRoleStatus -eq 'missing' -and -not $SkipPimRoleCheck" in CODE
    # The scope refusal must NOT honour the bypass - that gate is provable.
    scope_gate = CODE[CODE.index("Test-MgHasScope -Acceptable $MgWriteScopes)) {"):]
    assert "SkipPimRoleCheck" not in scope_gate[:400]


def test_role_requirement_depends_on_read_vs_write():
    """Global Reader can READ this plane but not write it, so a dry run must not demand a write
    role -- that would block the reporting use case the tool is mostly used for."""
    assert "$accept = if ($Apply) { $PimGroupWriteRoles } else { $PimGroupReadRoles }" in CODE
    write_block = CODE[CODE.index("$PimGroupWriteRoles = @("):]
    assert "'Global Reader'" not in write_block[:write_block.index(")")]


def test_pim_active_only_group_is_not_silently_dropped():
    """Two different kinds of PIM-managed group. A group held as a PIM ACTIVE assignment with no
    eligibility behind it has nothing to clone -- this script only creates eligibilities -- but
    it must not be granted as permanent membership either. Conflating the two excluded such a
    group from the membership plan while it never appeared in the eligibility plan, so it
    vanished from the run while the row claimed it had been 'copied as an eligibility'.

    An active-only group must remain visible as blocked rather than disappearing from the plan."""
    assert "$pimActiveOnlyIds" in CODE
    assert "BLOCKED-PIM-ACTIVE" in CODE
    # eligible and active-only must be distinct sets, not one merged bucket
    assert "if (-not $pimEligibleGroupIds.ContainsKey($g)) { $pimActiveOnlyIds[$g] = $true }" in CODE


def test_skip_pim_managed_text_matches_what_actually_happens():
    """The old wording promised an eligibility would be created; for active-only groups none
    was. A row that misdescribes itself is worse than one that blocks."""
    assert "re-created as an eligibility below" in CODE


def test_role_advice_narrows_for_role_assignable_groups():
    """For ROLE-ASSIGNABLE groups only Privileged Role Administrator and Global Administrator
    carry groupsAssignableToRoles/members/update; Directory Writers / Groups Administrator /
    Identity Governance Administrator / User Administrator cover non-role-assignable groups
    only. Listing all six regardless would send an operator to assign a role that still cannot
    make the call. The advice must also offer group OWNERSHIP, which is scoped to one group
    rather than the whole tenant and is the least-privilege answer."""
    assert "function Test-GroupRoleAssignable" in CODE
    assert "$anyRoleAssignable" in CODE
    assert "need one of: Privileged Role Administrator, Global Administrator" in SRC
    assert "do not carry groupsAssignableToRoles/members/update" in SRC
    assert "ACTIVE OWNER" in SRC
