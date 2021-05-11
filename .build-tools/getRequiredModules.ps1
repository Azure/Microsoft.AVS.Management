#!/usr/bin/pwsh

$requiredModules = @(
@{"ModuleName"="VMware.VimAutomation.Common";"ModuleVersion"="12.0.0.15939652"}
)

Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

foreach ($module in $requiredModules) {
    $targetModule = $module.ModuleName
    $targetVersion = $module.ModuleVersion
    Write-Host "Installing $targetModule-$targetVersion ...."
    Install-Module $targetModule -RequiredVersion $targetVersion
    Write-Host "----COMPLETED installation of $targetModule-$targetVersion----"
}


Write-Host "----SUCCESS: installed all required modules----"