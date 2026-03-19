---
description: "Review code changes for AVS scripting guideline compliance before creating a PR"
agent: "agent"
tools: ["read", "search"]
---
Review the current code changes against the AVS scripting guidelines and PR checklist. Use `#tool:get_changed_files` to find modified files, then analyze each one.

Check the full guidelines in [docs/README.md](../../docs/README.md) and the PR checklist in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Checklist

For each changed `.psm1` / `.ps1` file, verify:

### Structure
- [ ] Every exported function has `[CmdletBinding()]`
- [ ] Every exported function has `[AVSAttribute(timeout)]` with timeout ≤ 60 min
- [ ] Functions follow `Verb-Noun` naming per PowerShell guidelines
- [ ] Parameters use only supported types: `String`, `Double`, `Boolean`, `Int32`, `PSCredential`, `SecureString`
- [ ] No dynamic or conditional parameters

### Security
- [ ] All `String` parameters sanitized with `Limit-WildcardsandCodeInjectionCharacters` if involved in raw shell operations
- [ ] Names validated with `Test-AVSProtectedObjectName` before create/delete of policies, roles, users
- [ ] Secrets use `SecureString` / `PSCredential` — never logged or echoed
- [ ] No calls to `Connect-VIServer` or `Connect-SsoAdminServer`
- [ ] No elevation of `cloudadmins` privileges
- [ ] Appliance deployments use `[AVSSecureFolder]` for restricted access

### Error Handling
- [ ] Prerequisites validated before making changes (fail early)
- [ ] Changes tracked for rollback on partial failure
- [ ] Error messages include the failing entity and context
- [ ] `-ErrorAction Stop` used for fatal errors

### Output
- [ ] No unintended pipeline output (captured with `Out-Null` or variables)
- [ ] `$NamedOutputs` used correctly (max 32KB, set with `Set-Variable -Scope Global`)
- [ ] No child processes spawned

### Documentation & Manifest
- [ ] Functions have comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`)
- [ ] New functions added to `Export-ModuleMember` and `FunctionsToExport` in manifest
- [ ] Module version bumped following semver

### Tests
- [ ] Pester tests exist for new/modified functions
- [ ] `Invoke-ScriptAnalyzer -Settings PSGallery` passes with no errors

Report findings grouped by severity: **Blocking** (must fix), **Warning** (should fix), **Info** (suggestion).
