# Global Administrator (JIT) - the most privileged template in this repo. Read this before use.
#
# Grants an ELIGIBILITY for Global Administrator via standard PIM (PIM for Entra roles), NOT
# PIM for Groups and NOT a standing assignment. The holder is nothing until they activate; the
# activation is time-bound and logged.
#
# NO STANDING PATH EXISTS. The profile engine has no key for a standing directory role, so this
# file cannot be edited into one - DirectoryRoles is refused outright.
#
# THE GATES ARE NOT IN THIS FILE. MFA, justification, approval and activation duration live in
# the Global Administrator role's own PIM policy, because they apply to everyone eligible for
# the role rather than to one person. Assigning this eligibility while that policy allows
# self-approved activation gives someone a 30-second, unreviewed path to tenant-wide admin.
# CONFIRM THE POLICY REQUIRES APPROVAL before treating this as a control.
#
# Microsoft's guidance is that GA should be JIT and that a tenant keep at least two permanently
# excluded break-glass accounts - those stay standing and are deliberately NOT managed here.
#
# CONSENT: directory-role PIM is a separate scope family from PIM for Groups
# (RoleEligibilitySchedule.ReadWrite.Directory, not *.AzureADGroup). A tenant set up for the
# group plane is NOT automatically consented for this one; the launcher requests the extra
# scopes only when a profile uses this plane.
@{
    Name        = 'Global Administrator (JIT)'
    Description = 'Eligible for Global Administrator via standard PIM. No standing admin access.'

    # Standing access stays read-only, exactly as in the other admin profiles.
    Rbac = @(
        @{ Role = 'Reader'; Scope = 'root-mg' }
    )

    GroupMemberships      = @()
    PimGroupEligibilities = @()

    # Standard PIM (PIM for Entra roles). DirectoryScopeId is '/' - tenant-wide - which is the
    # only supported scope here; administrative-unit scoping is refused.
    # Duration is optional and clamped to the role's policy ceiling; omitted, it takes the
    # tenant default (DefaultEligibilityDuration in tenant.psd1).
    DirectoryRoleEligibilities = @(
        @{ Role = 'Global Administrator' }
    )
}
