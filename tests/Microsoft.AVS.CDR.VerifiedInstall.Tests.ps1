BeforeAll {
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
    Import-Module $modulePath -Force
    Import-Module Microsoft.PowerShell.PSResourceGet -Force

    function New-TestResource {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [string]$Version,

            [Parameter(Mandatory = $false)]
            [string]$Repository = 'TestRepo'
        )

        [pscustomobject]@{
            Name = $Name
            Version = $Version
            Repository = $Repository
        }
    }

    function New-TestMetadataXml {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ModuleName,

            [Parameter(Mandatory = $true)]
            [string]$BaseVersion,

            [Parameter(Mandatory = $false)]
            [string]$Prerelease,

            [Parameter(Mandatory = $true)]
            [string]$Repository,

            [Parameter(Mandatory = $true)]
            [string]$InstalledLocation,

            [Parameter(Mandatory = $true)]
            [string]$NormalizedVersion
        )

        $isPrerelease = if ($Prerelease) { 'true' } else { 'false' }
        $metadataPrereleaseLine = if ($Prerelease) { "      <S N=`"Prerelease`">$Prerelease</S>" } else { '' }
        $metadataPrereleaseValue = if ($Prerelease) { 'True' } else { 'False' }

@"
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCustomObject</T>
      <T>System.Object</T>
    </TN>
    <MS>
      <S N="Name">$ModuleName</S>
      <S N="Version">$BaseVersion</S>
      <Obj N="Type" RefId="1">
        <TN RefId="1">
          <T>Microsoft.PowerShell.PSResourceGet.UtilClasses.ResourceType</T>
          <T>System.Enum</T>
          <T>System.ValueType</T>
          <T>System.Object</T>
        </TN>
        <ToString>None</ToString>
        <I32>0</I32>
      </Obj>
      <S N="Description"></S>
      <S N="Author">Tests</S>
      <S N="CompanyName">Tests</S>
      <S N="Copyright"></S>
      <DT N="PublishedDate">2026-01-01T00:00:00-00:00</DT>
      <DT N="InstalledDate">2026-01-01T00:00:00-00:00</DT>
      <B N="IsPrerelease">$isPrerelease</B>
      <Nil N="UpdatedDate" />
      <Nil N="LicenseUri" />
      <Nil N="ProjectUri" />
      <Nil N="IconUri" />
      <Obj N="Tags" RefId="2">
        <TN RefId="2">
          <T>System.String[]</T>
          <T>System.Array</T>
          <T>System.Object</T>
        </TN>
        <LST />
      </Obj>
      <Obj N="Includes" RefId="3">
        <TN RefId="3">
          <T>System.Collections.Hashtable</T>
          <T>System.Object</T>
        </TN>
        <DCT />
      </Obj>
      <S N="PowerShellGetFormatVersion"></S>
      <S N="ReleaseNotes"></S>
      <Obj N="Dependencies" RefId="4">
        <TN RefId="4">
          <T>Microsoft.PowerShell.PSResourceGet.UtilClasses.Dependency[]</T>
          <T>System.Array</T>
          <T>System.Object</T>
        </TN>
        <LST />
      </Obj>
      <S N="RepositorySourceLocation">https://example.test/index.json</S>
      <S N="Repository">$Repository</S>
$metadataPrereleaseLine
      <Obj N="AdditionalMetadata" RefId="5">
        <TNRef RefId="0" />
        <MS>
          <S N="NormalizedVersion">$NormalizedVersion</S>
          <S N="IsPrerelease">$metadataPrereleaseValue</S>
        </MS>
      </Obj>
      <S N="InstalledLocation">$InstalledLocation</S>
    </MS>
  </Obj>
</Objs>
"@
    }

    function New-ModuleManifestContent {
        param(
            [Parameter(Mandatory = $true)]
            [object]$ModuleVersion,

            [Parameter(Mandatory = $false)]
            [object]$Prerelease
        )

        $ModuleVersion = [string]$ModuleVersion
        $Prerelease = if ($null -ne $Prerelease -and "$Prerelease" -ne '') { [string]$Prerelease } else { $null }

        $prereleaseBlock = if ($Prerelease) {
@"
    PrivateData = @{
        PSData = @{
            Prerelease = '$Prerelease'
        }
    }
"@
        }
        else {
            ''
        }

@"
@{
    RootModule = ''
    ModuleVersion = '$ModuleVersion'
    GUID = '11111111-1111-1111-1111-111111111111'
$prereleaseBlock
}
"@
    }

    function New-TestModuleLayout {
        param(
            [Parameter(Mandatory = $true)]
            [object]$BasePath,

            [Parameter(Mandatory = $true)]
            [object]$ModuleName,

            [Parameter(Mandatory = $true)]
            [object]$BaseVersion,

            [Parameter(Mandatory = $false)]
            [object]$Prerelease,

            [Parameter(Mandatory = $false)]
            [object]$Repository = 'TestRepo',

            [Parameter(Mandatory = $false)]
            [object]$InstalledLocation = $BasePath,

            [Parameter(Mandatory = $false)]
            [object]$NormalizedVersion,

            [Parameter(Mandatory = $false)]
            [switch]$WithoutMetadata
        )

        $BasePath = [string]$BasePath
        $ModuleName = [string]$ModuleName
        $BaseVersion = [string]$BaseVersion
        $Prerelease = if ($null -ne $Prerelease -and "$Prerelease" -ne '') { [string]$Prerelease } else { $null }
        $Repository = [string]$Repository
        $InstalledLocation = [string]$InstalledLocation
        $NormalizedVersion = if ($null -ne $NormalizedVersion -and "$NormalizedVersion" -ne '') { [string]$NormalizedVersion } else { $null }

        $moduleVersionDirectory = Join-Path (Join-Path $BasePath $ModuleName) $BaseVersion
        $null = New-Item -ItemType Directory -Path $moduleVersionDirectory -Force
        Set-Content -LiteralPath (Join-Path $moduleVersionDirectory "$ModuleName.psd1") `
            -Value (New-ModuleManifestContent -ModuleVersion $BaseVersion -Prerelease $Prerelease)
        Set-Content -LiteralPath (Join-Path $moduleVersionDirectory "$ModuleName.psm1") -Value '# stub'

        if (-not $WithoutMetadata) {
            $normalized = if ($NormalizedVersion) { $NormalizedVersion } elseif ($Prerelease) { "$BaseVersion-$Prerelease" } else { $BaseVersion }
            $metadataText = New-TestMetadataXml -ModuleName $ModuleName -BaseVersion $BaseVersion `
                -Prerelease $Prerelease -Repository $Repository -InstalledLocation $InstalledLocation `
                -NormalizedVersion $normalized

            Set-Content -LiteralPath (Join-Path $moduleVersionDirectory 'PSGetModuleInfo.xml') -Value $metadataText
        }

        $moduleVersionDirectory
    }

    Set-Item -Path function:global:New-TestMetadataXml -Value ${function:New-TestMetadataXml}
    Set-Item -Path function:global:New-ModuleManifestContent -Value ${function:New-ModuleManifestContent}
    Set-Item -Path function:global:New-TestModuleLayout -Value ${function:New-TestModuleLayout}
}

Describe 'Install-CdrVerifiedResources' {
    BeforeEach {
        $script:root = Join-Path $TestDrive 'ModulesRoot'
        $null = New-Item -ItemType Directory -Path $script:root -Force
    }

    It 'fails before any destination promotion when the install root is invalid' {
        $badRoot = Join-Path $TestDrive 'not-a-directory'
        Set-Content -LiteralPath $badRoot -Value 'file'
        $resources = @(New-TestResource -Name 'Broken.Root' -Version '3.2.4')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $badRoot, (, $resources) {
            param($badRoot, $resources)

            Mock Get-CdrLinuxModuleRoot { $badRoot }
            Mock Save-PSResource { throw 'should not download' }
            Mock Invoke-CdrDirectoryMove { }

            { Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser } |
                Should -Throw '*not a directory*'

            Should -Invoke Save-PSResource -Times 0
            Should -Invoke Invoke-CdrDirectoryMove -Times 0
        }
    }

    It 'prevents every destination promotion when a late dependency fails verification' {
        $resources = @(
            (New-TestResource -Name 'First.Module' -Version '3.2.4')
            (New-TestResource -Name 'Second.Module' -Version '3.2.4')
        )

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $moduleVersion = $Version
                $savePath = $Path
                $repositoryName = $Repository
                $versionInfo = Split-CdrResourceVersion -Version $moduleVersion
                New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion $versionInfo.BaseVersion `
                    -Prerelease $versionInfo.Prerelease -Repository $repositoryName -InstalledLocation $savePath | Out-Null
            }
            Mock Assert-CdrModuleSignature {
                param($ModuleDirectory, $ModuleName, $ModuleVersion)
                if ($ModuleName -eq 'Second.Module') {
                    throw 'late verification failure'
                }
            }
            Mock Invoke-CdrDirectoryMove { }

            { Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser } |
                Should -Throw '*late verification failure*'

            Should -Invoke Save-PSResource -Times 2
            Should -Invoke Invoke-CdrDirectoryMove -Times 0
            Test-Path -LiteralPath (Join-Path $root 'First.Module') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $root 'Second.Module') | Should -BeFalse
        }
    }

    It 'reuses an already installed exact-version copy and does not download it again' {
        $installedPath = New-TestModuleLayout -BasePath $script:root -ModuleName 'Installed.Module' `
            -BaseVersion '3.2.4' -Repository 'InstalledRepo' -InstalledLocation $script:root
        $resources = @(New-TestResource -Name 'Installed.Module' -Version '3.2.4' -Repository 'InstalledRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, $installedPath, (, $resources) {
            param($root, $installedPath, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource { throw 'should not download an installed exact version' }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                [pscustomobject]@{
                    Name = 'Installed.Module'
                    Version = [version]'3.2.4'
                    Repository = 'InstalledRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }

            Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser

            Should -Invoke Save-PSResource -Times 0
            Should -Invoke Assert-CdrModuleSignature -Times 1 -ParameterFilter { $ModuleDirectory -eq $installedPath }
        }
    }

    It 'requires full prerelease identity instead of trusting only the base-version directory name' {
        $resources = @(New-TestResource -Name 'Preview.Module' -Version '3.2.4-beta' -Repository 'PreviewRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath | Out-Null
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Invoke-CdrDirectoryMove { }

            { Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser } |
                Should -Throw '*prerelease*'

            Should -Invoke Invoke-CdrDirectoryMove -Times 0
        }
    }

    It 'forwards the selected repository to Save-PSResource' {
        $resources = @(New-TestResource -Name 'Repo.Module' -Version '3.2.4' -Repository 'SelectedRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath | Out-Null
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                [pscustomobject]@{
                    Name = 'Repo.Module'
                    Version = [version]'3.2.4'
                    Repository = 'SelectedRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }

            Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser

            Should -Invoke Save-PSResource -Times 1 -ParameterFilter {
                $Name -eq 'Repo.Module' -and
                $Repository -eq 'SelectedRepo' -and
                $SkipDependencyCheck -and
                $IncludeXml
            }
        }
    }

    It 'fails on a save error without retrying or redownloading the same resource' {
        $resources = @(New-TestResource -Name 'Broken.Download' -Version '3.2.4' -Repository 'SelectedRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource { throw 'save failed' }

            { Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser } |
                Should -Throw '*save failed*'

            Should -Invoke Save-PSResource -Times 1
        }
    }

    It 'rewrites PSGetModuleInfo.xml InstalledLocation while preserving repository and normalized version metadata' {
        $resources = @(New-TestResource -Name 'Metadata.Module' -Version '3.2.4' -Repository 'MetaRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath -NormalizedVersion '3.2.4' | Out-Null
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                [pscustomobject]@{
                    Name = 'Metadata.Module'
                    Version = [version]'3.2.4'
                    Repository = 'MetaRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }

            $null = Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser

            $metadataPath = Join-Path $root 'Metadata.Module/3.2.4/PSGetModuleInfo.xml'
            $info = $null
            $readError = $null
            [Microsoft.PowerShell.PSResourceGet.UtilClasses.PSResourceInfo]::TryRead($metadataPath, [ref]$info, [ref]$readError) | Should -BeTrue
            $readError | Should -BeNullOrEmpty
            $info.Repository | Should -Be 'MetaRepo'
            $info.InstalledLocation | Should -BeExactly $root
            $info.AdditionalMetadata['NormalizedVersion'] | Should -Be '3.2.4'
        }
    }

    It 'installs without touching a destination lock file (existing: <HasLegacyLock>)' -ForEach @(
        @{ HasLegacyLock = $false }
        @{ HasLegacyLock = $true }
    ) {
        $resources = @(New-TestResource -Name 'Unlocked.Module' -Version '3.2.4')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources), $HasLegacyLock {
            param($root, $resources, $HasLegacyLock)

            Mock Get-CdrLinuxModuleRoot { $root }
            $lockPath = Join-Path $root '.microsoft.avs.cdr.install.lock'
            if ($HasLegacyLock) {
                Set-Content -LiteralPath $lockPath -Value 'legacy lock contents' -NoNewline
            }

            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)

                Test-Path -LiteralPath $lockPath | Should -Be $HasLegacyLock
                if ($HasLegacyLock) {
                    Get-Content -LiteralPath $lockPath -Raw | Should -BeExactly 'legacy lock contents'
                }
                New-TestModuleLayout -BasePath $Path -ModuleName $Name -BaseVersion $Version `
                    -Repository $Repository -InstalledLocation $Path | Out-Null
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                [pscustomobject]@{
                    Name = 'Unlocked.Module'
                    Version = [version]'3.2.4'
                    Repository = 'TestRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }

            Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser

            Test-Path -LiteralPath (Join-Path $root 'Unlocked.Module/3.2.4/Unlocked.Module.psd1') |
                Should -BeTrue
            Test-Path -LiteralPath $lockPath | Should -Be $HasLegacyLock
            if ($HasLegacyLock) {
                Get-Content -LiteralPath $lockPath -Raw | Should -BeExactly 'legacy lock contents'
            }
        }
    }

    It 'rejects symlinked module roots to preserve same-filesystem promotion semantics' {
        if ($IsWindows) {
            Set-ItResult -Skipped -Because 'Linux-only symlink test'
        }

        $realRoot = Join-Path $TestDrive 'RealModules'
        $linkRoot = Join-Path $TestDrive 'LinkedModules'
        $null = New-Item -ItemType Directory -Path $realRoot -Force
        $null = New-Item -ItemType SymbolicLink -Path $linkRoot -Target $realRoot
        $resources = @(New-TestResource -Name 'Linked.Module' -Version '3.2.4')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $linkRoot, (, $resources) {
            param($linkRoot, $resources)

            Mock Get-CdrLinuxModuleRoot { $linkRoot }
            Mock Save-PSResource { throw 'should not download' }

            { Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser } |
                Should -Throw '*same-filesystem*'

            Should -Invoke Save-PSResource -Times 0
        }
    }

    It 'promotes staged modules and verifies discoverability in the actual CurrentUser module root' {
        $currentUserRoot = Join-Path $HOME '.local/share/powershell/Modules'
        $moduleName = "Copilot.Task3.$([guid]::NewGuid().ToString('N'))"
        $resource = New-TestResource -Name $moduleName -Version '3.2.4' -Repository 'DiscoveryRepo'
        $moduleRootToClean = Join-Path $currentUserRoot $moduleName

        if (Test-Path -LiteralPath $moduleRootToClean) {
            Remove-Item -LiteralPath $moduleRootToClean -Recurse -Force
        }

        try {
            InModuleScope Microsoft.AVS.CDR -ArgumentList $resource {
                param($resource)

                Mock Save-PSResource {
                    param($Name, $Version, $Path, $Repository)
                    $moduleName = $Name
                    $savePath = $Path
                    $repositoryName = $Repository
                    New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                        -Repository $repositoryName -InstalledLocation $savePath | Out-Null
                }
                Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }

                Install-CdrVerifiedResources -Resources @($resource) -Scope CurrentUser
            }

            $discovered = Get-PSResource -Name $moduleName -ErrorAction SilentlyContinue | Select-Object -First 1
            $discovered | Should -Not -BeNullOrEmpty
            $discovered.Repository | Should -Be 'DiscoveryRepo'
            $discovered.InstalledLocation | Should -BeExactly $currentUserRoot
        }
        finally {
            Remove-Item -LiteralPath $moduleRootToClean -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'supports an isolated AllUsers destination without requiring elevated changes' {
        $allUsersRoot = Join-Path $TestDrive 'AllUsersModules'
        $resources = @(New-TestResource -Name 'AllUsers.Module' -Version '3.2.4' -Repository 'SharedRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $allUsersRoot, (, $resources) {
            param($allUsersRoot, $resources)

            Mock Get-CdrLinuxModuleRoot { $allUsersRoot }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath | Out-Null
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                [pscustomobject]@{
                    Name = 'AllUsers.Module'
                    Version = [version]'3.2.4'
                    Repository = 'SharedRepo'
                    InstalledLocation = $allUsersRoot
                    Prerelease = $null
                }
            }

            Install-CdrVerifiedResources -Resources $resources -Scope AllUsers

            Test-Path -LiteralPath (Join-Path $allUsersRoot 'AllUsers.Module/3.2.4') | Should -BeTrue
        }
    }

    It 'backs up an exact-version destination before replacing it with -Force' {
        $existingPath = New-TestModuleLayout -BasePath $script:root -ModuleName 'Force.Module' `
            -BaseVersion '3.2.4' -Repository 'ForceRepo' -InstalledLocation $script:root
        Set-Content -LiteralPath (Join-Path $existingPath 'marker.txt') -Value 'old'
        $resources = @(New-TestResource -Name 'Force.Module' -Version '3.2.4' -Repository 'ForceRepo')

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                $path = New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath
                Set-Content -LiteralPath (Join-Path $path 'marker.txt') -Value 'new'
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                [pscustomobject]@{
                    Name = 'Force.Module'
                    Version = [version]'3.2.4'
                    Repository = 'ForceRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }

            Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser -Force

            Get-Content -LiteralPath (Join-Path $root 'Force.Module/3.2.4/marker.txt') | Should -Be 'new'
        }
    }

    It 'rolls back only the destinations owned by the failed promotion operation' {
        $preservedPath = New-TestModuleLayout -BasePath $script:root -ModuleName 'Unrelated.Module' `
            -BaseVersion '3.2.4' -Repository 'SharedRepo' -InstalledLocation $script:root
        $existingPath = New-TestModuleLayout -BasePath $script:root -ModuleName 'First.Module' `
            -BaseVersion '3.2.4' -Repository 'SharedRepo' -InstalledLocation $script:root
        Set-Content -LiteralPath (Join-Path $existingPath 'marker.txt') -Value 'original'

        $resources = @(
            (New-TestResource -Name 'First.Module' -Version '3.2.4' -Repository 'SharedRepo')
            (New-TestResource -Name 'Second.Module' -Version '3.2.4' -Repository 'SharedRepo')
        )

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                $path = New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath
                Set-Content -LiteralPath (Join-Path $path 'marker.txt') -Value "staged-$moduleName"
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                param($Name)
                [pscustomobject]@{
                    Name = $Name
                    Version = [version]'3.2.4'
                    Repository = 'SharedRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }
            Mock Invoke-CdrDirectoryMove {
                param($LiteralPath, $Destination)
                Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
                if ($Destination -like '*Second.Module*') {
                    throw 'promotion failed'
                }
            }

            { Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser -Force } |
                Should -Throw '*promotion failed*'
        }

        Get-Content -LiteralPath (Join-Path $script:root 'First.Module/3.2.4/marker.txt') | Should -Be 'original'
        Test-Path -LiteralPath (Join-Path $script:root 'Second.Module/3.2.4') | Should -BeFalse
        Test-Path -LiteralPath $preservedPath | Should -BeTrue
    }

    It 'retains recovery paths in the terminating error when rollback also fails' {
        $existingPath = New-TestModuleLayout -BasePath $script:root -ModuleName 'First.Module' `
            -BaseVersion '3.2.4' -Repository 'SharedRepo' -InstalledLocation $script:root
        Set-Content -LiteralPath (Join-Path $existingPath 'marker.txt') -Value 'original'

        $resources = @(
            (New-TestResource -Name 'First.Module' -Version '3.2.4' -Repository 'SharedRepo')
            (New-TestResource -Name 'Second.Module' -Version '3.2.4' -Repository 'SharedRepo')
        )

        InModuleScope Microsoft.AVS.CDR -ArgumentList $script:root, (, $resources) {
            param($root, $resources)

            Mock Get-CdrLinuxModuleRoot { $root }
            Mock Save-PSResource {
                param($Name, $Version, $Path, $Repository)
                $moduleName = $Name
                $savePath = $Path
                $repositoryName = $Repository
                $path = New-TestModuleLayout -BasePath $savePath -ModuleName $moduleName -BaseVersion '3.2.4' `
                    -Repository $repositoryName -InstalledLocation $savePath
                Set-Content -LiteralPath (Join-Path $path 'marker.txt') -Value "staged-$moduleName"
            }
            Mock Assert-CdrModuleSignature { param($ModuleDirectory, $ModuleName, $ModuleVersion) }
            Mock Get-PSResource {
                param($Name)
                [pscustomobject]@{
                    Name = $Name
                    Version = [version]'3.2.4'
                    Repository = 'SharedRepo'
                    InstalledLocation = $root
                    Prerelease = $null
                }
            }
            Mock Invoke-CdrDirectoryMove {
                param($LiteralPath, $Destination)
                if ($LiteralPath -like '*First.Module*' -and $Destination -like '*backups*') {
                    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
                    return
                }

                if ($LiteralPath -like '*staging*First.Module*' -and $Destination -like '*First.Module/3.2.4') {
                    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
                    return
                }

                if ($LiteralPath -like '*staging*Second.Module*' -and $Destination -like '*Second.Module/3.2.4') {
                    throw 'promotion failed'
                }

                if ($LiteralPath -like '*backups*First.Module*' -and $Destination -like '*First.Module/3.2.4') {
                    throw 'restore failed'
                }

                Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
            }

            {
                Install-CdrVerifiedResources -Resources $resources -Scope CurrentUser -Force
            } | Should -Throw '*rollback*backup*First.Module*'
        }

    }
}
