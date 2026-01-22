#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$modulesFolderPath,
    [Parameter(Mandatory=$true)][string]$accessToken
)

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

$script:zeroPSAnalyzerErrorsFound = $true
$script:zeroTestScriptFileInfoErrorsFound = $true
$script:zeroTestModuleManifestErrorsFound = $true
$script:zeroPesterErrorsFound = $true

function Get-PrevalidationResults {
    param (
        [string]$targetDir,
        $fileExtList
    )
    $scriptsToAnalyze = (Get-ChildItem "$targetDir\*" -Recurse -Include $fileExtList)

    # Four typed of severity from PSScriptAnalyzer: Information, Error, ParseError, Warning. See https://github.com/PowerShell/PSScriptAnalyzer/blob/e51d50864106998a65e05971eff69d95bb80aaba/Engine/Generic/DiagnosticRecord.cs#L129
    foreach ($script in $scriptsToAnalyze) {
        $analyzerOptions = @{Settings="PSGallery"; Path=($script.FullName)}
        $scriptIssues = (Invoke-ScriptAnalyzer @analyzerOptions)
        $scriptIssues | Format-Table @{Label="Severity";Alignment="Left"; Expression={$_.Severity}},ScriptName,RuleName,Message -Autosize

        $numberOfErrors = ($scriptIssues | Where-Object {$_.Severity -eq "Error" || $_.Severity -eq "ParseError"}).Count
        $numberOfWarnings = ($scriptIssues | Where-Object {$_.Severity -eq "Warning"}).Count
        $numberOfInfos = ($scriptIssues | Where-Object {$_.Severity -eq "Information"}).Count
        if ($numberOfErrors -gt 0) {
            $script:zeroPSAnalyzerErrorsFound = $false
        }

        [PSCustomObject]@{"# Errors" = $numberOfErrors; "# Warnings" = $numberOfWarnings; "# Information" = $numberOfInfos; "PS File" = $script.Name} | Format-Table
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

Write-Output "---- START: Pre-Validation----"

$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$fileExtList = @("*.ps1","*.psm1","*.psd1")

Get-PrevalidationResults (Join-Path -Path $repoRoot -ChildPath $modulesFolderPath) $fileExtList

# Check for and run Pester tests if they exist
$moduleFolderName = Split-Path -Leaf $modulesFolderPath
$testsDir = Join-Path -Path $repoRoot -ChildPath "tests"
$pesterTestFile = Join-Path -Path $testsDir -ChildPath "$moduleFolderName.Tests.ps1"

if (Test-Path $pesterTestFile) {
    Write-Output "Found Pester test file: $pesterTestFile"
    Write-Output "Running Pester tests..."
    
    $env:SKIP_INTEGRATION_TESTS = 'false'
    $Global:FeedSettings = @{ 
        Credential = [PSCredential]::new("ado", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))
        Repository = "ConsumptionV3"
    }
    
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $pesterTestFile
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
    Write-Output "No Pester test file found at: $pesterTestFile"
}

if (!$script:zeroPSAnalyzerErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: PSScriptAnalyzer found errors"
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
if (!$script:zeroPSAnalyzerErrorsFound -or !$script:zeroTestScriptFileInfoErrorsFound -or !$script:zeroTestModuleManifestErrorsFound -or !$script:zeroPesterErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: See above errors"
    Throw "Prevalidation failed"
} else {
    Write-Output "SUCCESS: completed pre-validation"
} 

Write-Output "---- END: Pre-Validation ----"