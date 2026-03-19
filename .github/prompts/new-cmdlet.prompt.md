---
description: "Scaffold a new AVS Run Command cmdlet with AVSAttribute, CmdletBinding, parameters, error handling, rollback, and documentation"
agent: "agent"
argument-hint: "Describe the cmdlet's purpose (e.g., 'configure NTP on all cluster hosts')"
---
Scaffold a new AVS Run Command cmdlet based on the user's description.

Read the [powershell-modules instructions](./../instructions/powershell-modules.instructions.md) and [powershell-scripts instructions](./../instructions/powershell-scripts.instructions.md) for conventions.

Generate the cmdlet with all of these elements:

1. **Comment-based help** with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, and `.EXAMPLE`
2. **`[CmdletBinding()]`** attribute
3. **`[AVSAttribute(timeout)]`** with appropriate timeout (max 60 min) and `UpdatesSDDC` flag
4. **Named parameters** using only supported types: `String`, `Double`, `Boolean`, `Int32`, `PSCredential`, `SecureString`
5. **Input validation**: sanitize strings with `Limit-WildcardsandCodeInjectionCharacters`, validate names with `Test-AVSProtectedObjectName` where applicable
6. **Prerequisite checks** before making changes (fail early pattern)
7. **Try/catch with rollback tracking** for operations that modify multiple entities — track changes in an array, undo on failure
8. **Output**: `Write-Host` for confirmations, `Write-Warning` for cautions, `throw` for fatal errors, suppress unintended output with `Out-Null`

Also remind the developer to:
- Add the function to `Export-ModuleMember` in the `.psm1` file
- Add the function to `FunctionsToExport` in the `.psd1` manifest
- Write Pester tests (suggest using `/add-test`)
