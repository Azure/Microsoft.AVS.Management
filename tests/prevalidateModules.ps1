#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$modulesFolderPath
)

$script:zeroPSAnalyzerErrorsFound = $true
$script:zeroTestScriptFileInfoErrorsFound = $true
$script:zeroTestModuleManifestErrorsFound = $true

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
        if ($numberOfErrorss -gt 0) {
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
                    $script:zeroTestScriptFileInfoErrorsFound = $false
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

if (!$script:zeroPSAnalyzerErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: PSScriptAnalyzer found errors"
}if (!$script:zeroTestScriptFileInfoErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: Test-PSScriptFileInfo found errors"
}if (!$script:zeroTestModuleManifestErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: Test-ModuleManifest found errors"
}if (!$script:zeroPSAnalyzerErrorsFound -or !$script:zeroTestScriptFileInfoErrorsFound -or !$script:zeroTestModuleManifestErrorsFound) {
    Write-Error -Message "PRE-VALIDATION FAILED: See above errors"
    Throw "Prevalidation failed"
}else {
    Write-Output "SUCCESS: completed pre-validation"
} 

Write-Output "---- END: Pre-Validation ----"