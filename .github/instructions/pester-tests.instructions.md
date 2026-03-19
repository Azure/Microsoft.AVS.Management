---
description: "Use when writing or editing Pester tests for AVS PowerShell modules. Covers test structure, mocking, parameter validation, and AVSAttribute verification patterns."
applyTo: "**/*.Tests.ps1"
---
# Pester Test Conventions

Framework: **Pester 5+**. Reference: [Microsoft.AVS.Management.Tests.ps1](../../tests/Microsoft.AVS.Management.Tests.ps1).

## Setup Pattern

```powershell
BeforeAll {
    # Define AVSAttribute locally if not already loaded (avoids PowerCLI dependency in tests)
    if (-not ('AVSAttribute' -as [type])) {
        class AVSAttribute : Attribute {
            [bool]$UpdatesSDDC = $false
            [TimeSpan]$Timeout
            [bool]$AutomationOnly = $false
            AVSAttribute([int]$timeoutMinutes) { $this.Timeout = New-TimeSpan -Minutes $timeoutMinutes }
        }
    }
    Import-Module "$PSScriptRoot/../ModuleName/ModuleName.psd1" -Force
}
```

## Test Categories

### 1. Parameter Validation (via `Get-Command` reflection)
```powershell
It "ClusterName should be mandatory String" {
    $cmd = Get-Command Set-Example
    $param = $cmd.Parameters['ClusterName']
    $param.ParameterType.Name | Should -Be 'String'
    $param.Attributes.Where({ $_ -is [Parameter] }).Mandatory | Should -Be $true
}
```

### 2. AVSAttribute Verification
```powershell
It "should have AVSAttribute with correct timeout" {
    $cmd = Get-Command Set-Example
    $attr = $cmd.ScriptBlock.Attributes.Where({ $_ -is [AVSAttribute] })
    $attr.Count | Should -Be 1
    $attr[0].Timeout.TotalMinutes | Should -BeLessOrEqual 60
}
```

### 3. Function Behavior (via mocking)
```powershell
It "should throw when cluster not found" {
    Mock Get-Cluster { $null }
    { Set-Example -ClusterName 'missing' } | Should -Throw -ExpectedMessage "*not found*"
}
```

### 4. Cleanup Verification
```powershell
It "should clean up PSDrive on failure" {
    Mock New-PSDrive { throw "disk error" }
    { Set-Example } | Should -Throw
    Should -Invoke Remove-PSDrive -ModuleName ModuleName
}
```

## Mocking Guidelines

- Mock external/PowerCLI cmdlets: `Get-Cluster`, `Get-Datastore`, `Get-VMHost`, `Invoke-WebRequest`, `New-Item`
- Use `-ModuleName` parameter when the mock target is called inside a module
- Use `-ParameterFilter` for targeted mock assertions
- Never mock the function under test — only its dependencies
