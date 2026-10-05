#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$psdPath,
    [switch]$SkipPrereq
)
$ErrorActionPreference = "Stop"
if (-not $SkipPrereq) {
    $cdrManifestPath = Join-Path $PSScriptRoot "../Microsoft.AVS.CDR/Microsoft.AVS.CDR.psd1"
    $cdrManifest = Import-PowerShellDataFile -Path $cdrManifestPath
    $openAuthenticodeDependency = @($cdrManifest.RequiredModules | Where-Object {
        $_.ModuleName -eq "OpenAuthenticode"
    })

    if ($openAuthenticodeDependency.Count -ne 1 -or -not $openAuthenticodeDependency[0].RequiredVersion) {
        throw "Microsoft.AVS.CDR must declare exactly one OpenAuthenticode RequiredModules entry with RequiredVersion."
    }

    $requiredModules = @(
        @{ Name = "Pester"; Version = "5.7.1" }
        @{ Name = "OpenAuthenticode"; Version = $openAuthenticodeDependency[0].RequiredVersion }
    )
    foreach ($module in $requiredModules) {
        Write-Host "Installing $($module.Name)@$($module.Version) ...."
        Find-PSResource $module.Name -Version $module.Version -IncludeDependencies -Repository Consumption | Install-PSResource -Verbose -SkipDependencyCheck
    }

    & pwsh -NoProfile -File $PSCommandPath -psdPath $psdPath -SkipPrereq
    if( $LASTEXITCODE -ne 0 ) {
        throw "Failed to get required modules."
    }
}
else 
{
    $cdr = Join-Path $PSScriptRoot "../Microsoft.AVS.CDR"
    import-module $cdr -Verbose

    Install-PSResourceDependencies -ManifestPath $psdPath -Repository Consumption -Verbose
}
