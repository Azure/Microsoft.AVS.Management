#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$modulesFolderPath
)

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

$script:zeroTestScriptFileInfoErrorsFound = $true
$script:zeroTestModuleManifestErrorsFound = $true
$script:zeroPesterErrorsFound = $true

function Get-PrevalidationResults {
    param (
        [string]$targetDir,
        $fileExtList
    )
    $scriptsToValidate = (Get-ChildItem "$targetDir\*" -Recurse -Include $fileExtList)

    foreach ($script in $scriptsToValidate) {
        $fileExtension = ($script.Extension)
        switch ($fileExtension) {
            ".ps1" { 
                Write-Output "Found extension $fileExtension. Running 'Test-PSScriptFileInfo' on $($script.Name)"
                Test-PSScriptFileInfo -Path ($script.FullName)
                if (!$?) {
                    $script:zeroTestScriptFileInfoErrorsFound = $false
                }
                Write-Output "Errors found in script: $(!$script:zeroTestScriptFileInfoErrorsFound)"
            }
            ".psd1" {
                Write-Output "Found extension $fileExtension. Running 'Test-ModuleManifest' on $($script.Name)"
                Test-ModuleManifest -Path ($script.FullName)
                if (!$?) {
                    $script:zeroTestModuleManifestErrorsFound = $false
                }
                Write-Output "Errors found in manifest: $(!$script:zeroTestModuleManifestErrorsFound)"
             }
            Default {
                Write-Output "No other pre-validation performed for $($script.Name)"
            }
        }
    }
}

function Get-PesterTestPaths {
    param(
        [Parameter(Mandatory = $true)][string]$testsDir,
        [Parameter(Mandatory = $true)][string]$moduleFolderName
    )

    $pesterTestPaths = @()
    $basePesterTestFile = Join-Path -Path $testsDir -ChildPath "$moduleFolderName.Tests.ps1"

    if (Test-Path $basePesterTestFile) {
        $pesterTestPaths += $basePesterTestFile
    }

    if ($moduleFolderName -eq 'Microsoft.AVS.CDR') {
        $pesterTestPaths += Get-ChildItem -Path $testsDir -Filter 'Microsoft.AVS.CDR.*.Tests.ps1' -File |
            Sort-Object -Property Name |
            Select-Object -ExpandProperty FullName
    }

    return $pesterTestPaths
}

Write-Output "---- START: Pre-Validation----"

$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$fileExtList = @("*.ps1","*.psm1","*.psd1")

Get-PrevalidationResults (Join-Path -Path $repoRoot -ChildPath $modulesFolderPath) $fileExtList

# Check for and run Pester tests if they exist
$moduleFolderName = Split-Path -Leaf $modulesFolderPath
$testsDir = Join-Path -Path $repoRoot -ChildPath "tests"
$pesterTestFiles = @(Get-PesterTestPaths -testsDir $testsDir -moduleFolderName $moduleFolderName)

if ($pesterTestFiles.Count -gt 0) {
    Write-Output "Found Pester test file(s): $($pesterTestFiles -join ', ')"
    Write-Output "Running Pester tests..."
    
    $env:SKIP_INTEGRATION_TESTS = 'false'
    $Global:FeedSettings = @{ 
        Repository = "Consumption"
    }
    
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $pesterTestFiles
    $pesterConfig.Run.Exit = $false
    $pesterConfig.Output.Verbosity = 'Detailed'
    $pesterConfig.Should.ErrorAction = 'Continue'
    $env:SKIP_INTEGRATION_TESTS = $true
    $pesterResults = Invoke-Pester -Configuration $pesterConfig
    
    if ($pesterResults.FailedCount -gt 0) {
        $script:zeroPesterErrorsFound = $false
        Write-Error -Message "Pester tests failed: $($pesterResults.FailedCount) test(s) failed"
    } else {
        Write-Output "SUCCESS: All Pester tests passed ($($pesterResults.PassedCount) passed)"
    }
} else {
    Write-Output "No Pester test files found for module: $moduleFolderName"
}

if (!$script:zeroTestScriptFileInfoErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: Test-PSScriptFileInfo found errors"
}
if (!$script:zeroTestModuleManifestErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: Test-ModuleManifest found errors"
}
if (!$script:zeroPesterErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: Pester tests failed"
}
if (!$script:zeroTestScriptFileInfoErrorsFound -or !$script:zeroTestModuleManifestErrorsFound -or !$script:zeroPesterErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: See above errors"
    Throw "Prevalidation failed"
} else {
    Write-Output "SUCCESS: completed pre-validation"
} 

Write-Output "---- END: Pre-Validation ----"