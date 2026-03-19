---
description: "Generate Pester 5 tests for an AVS cmdlet covering parameter validation, AVSAttribute verification, mocking, and error scenarios"
agent: "agent"
argument-hint: "Name of the cmdlet to test (e.g., 'Set-VmfsIscsi')"
---
Generate Pester 5 tests for the specified AVS cmdlet.

Read the [pester-tests instructions](./../instructions/pester-tests.instructions.md) for conventions and the cmdlet source code to understand its parameters, behavior, and error paths.

Reference [Microsoft.AVS.Management.Tests.ps1](../../tests/Microsoft.AVS.Management.Tests.ps1) for the canonical test patterns used in this project.

Generate tests covering:

1. **`BeforeAll` setup**: define `AVSAttribute` class locally if not loaded, import the module with `-Force`
2. **Parameter validation**: use `Get-Command` to verify each parameter's type, mandatory status, and attributes
3. **AVSAttribute verification**: confirm timeout value, `UpdatesSDDC`, and `AutomationOnly` flags
4. **Success path**: mock dependencies (PowerCLI cmdlets, utility functions) and verify the function completes without error
5. **Error scenarios**: test each failure path — missing resources, invalid inputs, partial failures
6. **Cleanup verification**: if the function uses try/finally patterns, verify cleanup happens even on failure (e.g., `Remove-PSDrive`)
7. **Error messages**: use `Should -Throw -ExpectedMessage` to verify error messages include context

Use `-ModuleName` on mocks when the target cmdlet is inside a module. Never mock the function under test.
