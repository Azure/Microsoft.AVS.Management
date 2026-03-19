---
description: "Use when creating or editing PowerShell script files (.ps1) for AVS — utility functions, helpers, and class definitions. Covers error handling, validation, output, and security patterns."
applyTo: "**/*.ps1"
---
# PowerShell Script Conventions

## Error Handling

1. **Validate before acting** — check all prerequisites before making changes. Fail early.
   ```powershell
   $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Ignore
   if (-not $Cluster) { throw "Cluster '$ClusterName' not found." }
   ```

2. **Track changes for rollback** on partial failure. See `Set-VmfsIscsi` in [Microsoft.AVS.VMFS](../../Microsoft.AVS.VMFS/Microsoft.AVS.VMFS.psm1):
   ```powershell
   $ConfiguredHosts = @()
   foreach ($VMHost in $VMHosts) {
       try {
           # make change, then track
           $ConfiguredHosts += @{ VMHost = $VMHost; Changed = $true }
       } catch {
           # rollback everything from this run
           foreach ($Entry in $ConfiguredHosts) { <# undo #> }
           throw "Failed on $($VMHost.Name): $($_.Exception.Message)"
       }
   }
   ```

3. **Wrap context in error messages** — always include the failing entity:
   ```powershell
   throw "Failed to set storage policy on cluster '$ClusterName': $($_.Exception.Message)"
   ```

4. Use `-ErrorAction Stop` for fatal errors, `-ErrorAction Ignore` for optional lookups.

## Security

- Sanitize string inputs with `Limit-WildcardsandCodeInjectionCharacters` before use.
- Validate against `Test-AVSProtectedObjectName` before creating/deleting policies, roles, or users.
- Never log `SecureString` or `PSCredential` values.
- Never call `Connect-VIServer` or `Connect-SsoAdminServer` — sessions are pre-established.

## Output

- `Write-Host` for user-facing confirmations.
- `Write-Warning` for cautions.
- `Write-Error` + `throw` for failures.
- Suppress unintended output with `Out-Null` or variable capture — stray output disrupts other streams.
- Use `$NamedOutputs` hashtable (max 32KB) with `Set-Variable -Name NamedOutputs -Scope Global` for structured ARM results.

## Documentation

Include comment-based help for every function:

```powershell
<#
.SYNOPSIS Brief description.
.DESCRIPTION Detailed description.
.PARAMETER Name Parameter description.
.EXAMPLE
    Example-Usage -Name "value"
#>
```
