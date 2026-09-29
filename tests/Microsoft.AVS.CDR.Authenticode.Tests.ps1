BeforeAll {
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
    Import-Module $modulePath -Force
    Import-Module OpenAuthenticode -Force

    function New-TestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=Microsoft.AVS.CDR Tests",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false))

        $request.CreateSelfSigned(
            [datetimeoffset]::UtcNow.AddDays(-1),
            [datetimeoffset]::UtcNow.AddDays(7))
    }

    function New-TrustStore {
        param(
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
        )

        $trustStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $trustStore.Add($Certificate) | Out-Null
        $trustStore
    }

    function New-SignedPowerShellFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$LiteralPath,

            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

            [Parameter(Mandatory = $true)]
            [string]$Content
        )

        Set-Content -LiteralPath $LiteralPath -Value $Content
        Set-OpenAuthenticodeSignature -LiteralPath $LiteralPath -Certificate $Certificate -ErrorAction Stop | Out-Null
    }

    function New-CdrFixtureModule {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ModulesRoot,

            [Parameter(Mandatory = $true)]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [string]$Version,

            [Parameter(Mandatory = $false)]
            [string]$Prerelease,

            [Parameter(Mandatory = $false)]
            [string]$SentinelVariableName,

            [Parameter(Mandatory = $false)]
            [string]$SentinelValue,

            [Parameter(Mandatory = $false)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
        )

        $moduleVersionPath = Join-Path -Path (Join-Path -Path $ModulesRoot -ChildPath $Name) -ChildPath $Version
        $manifestPath = Join-Path -Path $moduleVersionPath -ChildPath "$Name.psd1"
        $moduleScriptPath = Join-Path -Path $moduleVersionPath -ChildPath "$Name.psm1"

        New-Item -ItemType Directory -Path $moduleVersionPath -Force | Out-Null

        $moduleScript = if ($SentinelVariableName) {
@"
if (-not (Get-Variable -Name '$SentinelVariableName' -Scope Global -ErrorAction SilentlyContinue)) {
    `$global:$SentinelVariableName = @()
}
`$global:$SentinelVariableName = @(`$global:$SentinelVariableName) + '$SentinelValue'
"@
        }
        else {
            '# fixture module'
        }

        if ($Certificate) {
            New-SignedPowerShellFile -LiteralPath $moduleScriptPath -Certificate $Certificate -Content $moduleScript
        }
        else {
            Set-Content -LiteralPath $moduleScriptPath -Value $moduleScript
        }

        $manifestParams = @{
            Path = $manifestPath
            RootModule = "$Name.psm1"
            ModuleVersion = $Version
            FunctionsToExport = @()
            CmdletsToExport = @()
            VariablesToExport = @()
            AliasesToExport = @()
        }
        if ($Prerelease) {
            $manifestParams['Prerelease'] = $Prerelease
        }

        New-ModuleManifest @manifestParams | Out-Null

        if ($Certificate) {
            Set-OpenAuthenticodeSignature -LiteralPath $manifestPath -Certificate $Certificate -ErrorAction Stop | Out-Null
        }

        [pscustomobject]@{
            Name = $Name
            Version = if ($Prerelease) { "$Version-$Prerelease" } else { $Version }
            ModuleVersionPath = $moduleVersionPath
            ManifestPath = $manifestPath
        }
    }
}

Describe "Assert-CdrFileSignature" {
    Context "Mocked backend behavior" {
        It "rejects an unsigned backend result" {
            InModuleScope Microsoft.AVS.CDR {
                Mock 'OpenAuthenticode\Get-OpenAuthenticodeSignature' { @() }

                {
                    Assert-CdrFileSignature -LiteralPath '/fixture/Module.psm1' `
                        -ModuleName 'Fixture' -ModuleVersion '1.0.0'
                } | Should -Throw '*No Authenticode signature*'
            }
        }

        It "wraps backend errors with module context" {
            InModuleScope Microsoft.AVS.CDR {
                Mock 'OpenAuthenticode\Get-OpenAuthenticodeSignature' { throw 'backend blew up' }

                {
                    Assert-CdrFileSignature -LiteralPath '/fixture/Module.psm1' `
                        -ModuleName 'Fixture' -ModuleVersion '1.0.0'
                } | Should -Throw '*Fixture*1.0.0*/fixture/Module.psm1*backend blew up*'
            }
        }

        It "rejects partial output followed by a backend error" {
            InModuleScope Microsoft.AVS.CDR {
                Mock 'OpenAuthenticode\Get-OpenAuthenticodeSignature' {
                    [pscustomobject]@{ SignerCertificate = [pscustomobject]@{ Subject = 'CN=Signer' } }
                    throw 'late backend failure'
                }

                {
                    Assert-CdrFileSignature -LiteralPath '/fixture/Module.psm1' `
                        -ModuleName 'Fixture' -ModuleVersion '1.0.0'
                } | Should -Throw '*late backend failure*'
            }
        }

        It "accepts a valid backend result without leaking output" {
            InModuleScope Microsoft.AVS.CDR {
                Mock 'OpenAuthenticode\Get-OpenAuthenticodeSignature' {
                    [pscustomobject]@{ SignerCertificate = [pscustomobject]@{ Subject = 'CN=Signer' } }
                }

                $result = Assert-CdrFileSignature -LiteralPath '/fixture/Module.psm1' `
                    -ModuleName 'Fixture' -ModuleVersion '1.0.0'

                $result | Should -BeNullOrEmpty
                Should -Invoke 'OpenAuthenticode\Get-OpenAuthenticodeSignature' -Times 1 -Exactly -ParameterFilter {
                    $LiteralPath -eq '/fixture/Module.psm1' -and
                    $ErrorAction -eq 'Stop' -and
                    -not $SkipCertificateCheck -and
                    -not $TrustStore
                }
            }
        }

        It "accepts multiple signatures from the backend" {
            InModuleScope Microsoft.AVS.CDR {
                Mock 'OpenAuthenticode\Get-OpenAuthenticodeSignature' {
                    [pscustomobject]@{ SignerCertificate = [pscustomobject]@{ Subject = 'CN=Signer One' } }
                    [pscustomobject]@{ SignerCertificate = [pscustomobject]@{ Subject = 'CN=Signer Two' } }
                }

                {
                    Assert-CdrFileSignature -LiteralPath '/fixture/Module.psm1' `
                        -ModuleName 'Fixture' -ModuleVersion '1.0.0'
                } | Should -Not -Throw
            }
        }
    }
}

Describe "Assert-CdrModuleSignature" {
    It "verifies hidden files and case-insensitive supported extensions only" {
        $moduleDir = Join-Path $TestDrive "FixtureModule-Hidden"
        $null = New-Item -ItemType Directory -Path $moduleDir -Force
        $null = New-Item -ItemType Directory -Path (Join-Path $moduleDir 'bin')

        Set-Content -LiteralPath (Join-Path $moduleDir 'Fixture.psd1') -Value '@{}'
        Set-Content -LiteralPath (Join-Path $moduleDir '.hidden.PS1') -Value "Write-Output 'hidden'"
        Set-Content -LiteralPath (Join-Path $moduleDir 'Fixture.PS1XML') -Value '<Types />'
        Set-Content -LiteralPath (Join-Path $moduleDir 'README.md') -Value '# ignored'
        Set-Content -LiteralPath (Join-Path $moduleDir 'bin/Native.DLL') -Value 'binary placeholder'
        Set-Content -LiteralPath (Join-Path $moduleDir 'bin/config.json') -Value '{}'

        InModuleScope Microsoft.AVS.CDR -ArgumentList $moduleDir {
            param($moduleDir)

            Mock Assert-CdrFileSignature { }

            $verbose = Assert-CdrModuleSignature -ModuleDirectory $moduleDir `
                -ModuleName 'Fixture' -ModuleVersion '1.0.0' -Verbose 4>&1

            $verbose.Message | Should -Match 'Verified 4 supported file\(s\)'
            Should -Invoke Assert-CdrFileSignature -Times 4 -Exactly
            Should -Invoke Assert-CdrFileSignature -Times 1 -ParameterFilter { $LiteralPath -eq (Join-Path $moduleDir 'Fixture.psd1') }
            Should -Invoke Assert-CdrFileSignature -Times 1 -ParameterFilter { $LiteralPath -eq (Join-Path $moduleDir '.hidden.PS1') }
            Should -Invoke Assert-CdrFileSignature -Times 1 -ParameterFilter { $LiteralPath -eq (Join-Path $moduleDir 'Fixture.PS1XML') }
            Should -Invoke Assert-CdrFileSignature -Times 1 -ParameterFilter { $LiteralPath -eq (Join-Path $moduleDir 'bin/Native.DLL') }
            Should -Invoke Assert-CdrFileSignature -Times 0 -ParameterFilter { $LiteralPath -eq (Join-Path $moduleDir 'README.md') }
            Should -Invoke Assert-CdrFileSignature -Times 0 -ParameterFilter { $LiteralPath -eq (Join-Path $moduleDir 'bin/config.json') }
        }
    }

    It "fails when the module manifest is missing" {
        $moduleDir = Join-Path $TestDrive "FixtureModule-MissingManifest"
        $null = New-Item -ItemType Directory -Path $moduleDir -Force
        Set-Content -LiteralPath (Join-Path $moduleDir 'script.ps1') -Value "Write-Output 'hi'"

        InModuleScope Microsoft.AVS.CDR -ArgumentList $moduleDir {
            param($moduleDir)

            {
                Assert-CdrModuleSignature -ModuleDirectory $moduleDir `
                    -ModuleName 'Fixture' -ModuleVersion '1.0.0'
            } | Should -Throw '*Fixture.psd1*'
        }
    }

    It "treats unreadable directories as verification failures" {
        if ($IsWindows) {
            Set-ItResult -Skipped -Because 'Linux-only permission test'
        }

        $moduleDir = Join-Path $TestDrive "FixtureModule-Unreadable"
        $blockedDir = Join-Path $moduleDir 'blocked'
        $null = New-Item -ItemType Directory -Path $blockedDir -Force
        Set-Content -LiteralPath (Join-Path $moduleDir 'Fixture.psd1') -Value '@{}'
        Set-Content -LiteralPath (Join-Path $blockedDir 'script.ps1') -Value "Write-Output 'hi'"

        try {
            & chmod 000 $blockedDir

            InModuleScope Microsoft.AVS.CDR -ArgumentList $moduleDir {
                param($moduleDir)

                {
                    Assert-CdrModuleSignature -ModuleDirectory $moduleDir `
                        -ModuleName 'Fixture' -ModuleVersion '1.0.0'
                } | Should -Throw '*Failed to enumerate*'
            }
        }
        finally {
            & chmod 755 $blockedDir
        }
    }

    It "rejects symlinks or reparse points in the module tree" {
        $moduleDir = Join-Path $TestDrive "FixtureModule-Symlink"
        $targetPath = Join-Path $moduleDir 'target.ps1'
        $linkPath = Join-Path $moduleDir 'linked.ps1'

        $null = New-Item -ItemType Directory -Path $moduleDir -Force
        Set-Content -LiteralPath (Join-Path $moduleDir 'Fixture.psd1') -Value '@{}'
        Set-Content -LiteralPath $targetPath -Value "Write-Output 'target'"
        $null = New-Item -ItemType SymbolicLink -Path $linkPath -Target $targetPath

        InModuleScope Microsoft.AVS.CDR -ArgumentList $moduleDir {
            param($moduleDir)

            {
                Assert-CdrModuleSignature -ModuleDirectory $moduleDir `
                    -ModuleName 'Fixture' -ModuleVersion '1.0.0'
            } | Should -Throw '*symlink*'
        }
    }
}

Describe "Assert-CdrResolvedModuleSignatures" {
    It "preflights every resolved module location" {
        $modules = @(
            [pscustomobject]@{
                Name = 'One'
                Version = '1.0.0'
                InstalledLocation = (Join-Path $TestDrive 'One/1.0.0')
            }
            [pscustomobject]@{
                Name = 'Two'
                Version = '2.0.0'
                InstalledLocation = (Join-Path $TestDrive 'Two/2.0.0')
            }
        )

        foreach ($module in $modules) {
            $null = New-Item -ItemType Directory -Path $module.InstalledLocation -Force
            Set-Content -LiteralPath (Join-Path $module.InstalledLocation "$($module.Name).psd1") -Value '@{}'
            Set-Content -LiteralPath (Join-Path $module.InstalledLocation "$($module.Name).psm1") -Value '# script'
        }

        $invocations = InModuleScope Microsoft.AVS.CDR -ArgumentList (, $modules) {
            param($modules)

            $script:recordedPaths = [System.Collections.Generic.List[string]]::new()
            function Assert-CdrFileSignature {
                param([string]$LiteralPath)
                $script:recordedPaths.Add($LiteralPath) | Out-Null
            }

            Assert-CdrResolvedModuleSignatures -Modules $modules
            @($script:recordedPaths)
        }

        $invocations | Should -Contain (Join-Path $modules[0].InstalledLocation 'One.psd1')
        $invocations | Should -Contain (Join-Path $modules[0].InstalledLocation 'One.psm1')
        $invocations | Should -Contain (Join-Path $modules[1].InstalledLocation 'Two.psd1')
        $invocations | Should -Contain (Join-Path $modules[1].InstalledLocation 'Two.psm1')
        $invocations.Count | Should -Be 4
    }
}

Describe "Import entry points with Authenticode checks" {
    BeforeEach {
        $script:originalPSModulePath = $env:PSModulePath
    }

    AfterEach {
        $env:PSModulePath = $script:originalPSModulePath
        Get-Variable -Name 'CdrImportSentinel' -Scope Global -ErrorAction SilentlyContinue | Remove-Variable -Scope Global -Force -ErrorAction SilentlyContinue
        foreach ($moduleName in @(
            'VerifiedStableModule'
            'VerifiedPrereleaseModule'
            'VerifiedDependencyModule'
            'ShadowedCheckedModule'
            'BadDependencyModule'
            'LoadedModuleFixture'
            'LoadedDependencyFixture'
        )) {
            Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
        }
    }

    It "verifies an empty dependency manifest before returning in checked mode" {
        $manifestPath = Join-Path $TestDrive 'EmptyManifest.psd1'
@"
@{
    RootModule = 'EmptyManifest.psm1'
    ModuleVersion = '1.0.0'
}
"@ | Set-Content -LiteralPath $manifestPath

        InModuleScope Microsoft.AVS.CDR -ArgumentList $manifestPath {
            param($manifestPath)

            Mock Assert-CdrFileSignature { }
            Mock Build-InstalledDependencyGraph { throw 'should not resolve dependencies' }
            Mock Import-Module { throw 'should not import modules' }

            $result = Import-PSResourceDependencies -ManifestPath $manifestPath -AuthenticodeCheck

            $result | Should -BeNullOrEmpty
            Should -Invoke Assert-CdrFileSignature -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -eq $manifestPath -and
                $ModuleName -eq 'EmptyManifest' -and
                $ModuleVersion -eq '1.0.0'
            }
            Should -Invoke Build-InstalledDependencyGraph -Times 0 -Exactly
            Should -Invoke Import-Module -Times 0 -Exactly
        }
    }

    It "preflights the full graph before importing any checked dependency" {
        $certificate = New-TestCertificate
        $modulesRoot = Join-Path $TestDrive 'modules'
        $validDependency = New-CdrFixtureModule -ModulesRoot $modulesRoot `
            -Name 'VerifiedDependencyModule' -Version '1.0.0' `
            -SentinelVariableName 'CdrImportSentinel' -SentinelValue 'imported' `
            -Certificate $certificate

        InModuleScope Microsoft.AVS.CDR -ArgumentList $validDependency {
            param($validDependency)

            Mock Get-PSResourcesPinned {
                @(
                    [pscustomobject]@{
                        Name = $validDependency.Name
                        Version = $validDependency.Version
                        InstalledLocation = $validDependency.ModuleVersionPath
                        Dependencies = @()
                    }
                    [pscustomobject]@{
                        Name = 'BadDependencyModule'
                        Version = '2.0.0'
                        InstalledLocation = '/bad/dependency/2.0.0'
                        Dependencies = @()
                    }
                )
            }

            Mock Get-Module { @() }
            Mock Assert-CdrResolvedModuleSignatures {
                param([object[]]$Modules)
                $Modules[0].Name | Should -Be $validDependency.Name
                $Modules[1].Name | Should -Be 'BadDependencyModule'
                throw "Module 'BadDependencyModule' version '2.0.0' failed signature verification."
            }
            Mock Import-Module {
                Microsoft.PowerShell.Core\Import-Module -Name $Name -Global:$Global `
                    -DisableNameChecking:$DisableNameChecking -Force:$Force -ErrorAction $ErrorAction
            }

            {
                Import-ModulePinned -Name 'RootModule' -RequiredVersion '9.9.9' -AuthenticodeCheck
            } | Should -Throw '*BadDependencyModule*failed signature verification*'

            Should -Invoke Assert-CdrResolvedModuleSignatures -Times 1 -Exactly
            Should -Invoke Import-Module -Times 0 -Exactly
        }

        $global:CdrImportSentinel | Should -BeNullOrEmpty
    }

    It "reuses a matching loaded module only when its ModuleBase matches the verified path" {
        InModuleScope Microsoft.AVS.CDR {
            $verifiedPath = '/verified/LoadedModuleFixture/1.2.3'
            Mock Get-PSResourcesPinned {
                @(
                    [pscustomobject]@{
                        Name = 'LoadedModuleFixture'
                        Version = '1.2.3'
                        InstalledLocation = $verifiedPath
                        Dependencies = @()
                    }
                )
            }
            Mock Assert-CdrResolvedModuleSignatures { }
            Mock Get-Module {
                [pscustomobject]@{
                    Name = 'LoadedModuleFixture'
                    Version = [version]'1.2.3'
                    ModuleBase = $verifiedPath
                }
            }
            Mock Import-Module { throw 'should not import a matching loaded module' }

            $result = Import-ModulePinned -Name 'LoadedModuleFixture' -RequiredVersion '1.2.3' -AuthenticodeCheck -PassThru

            $result.Name | Should -Be 'LoadedModuleFixture'
            $result.ModuleBase | Should -BeExactly $verifiedPath
            Should -Invoke Assert-CdrResolvedModuleSignatures -Times 1 -Exactly
            Should -Invoke Import-Module -Times 0 -Exactly
        }
    }

    It "rejects a loaded stable module from a different path in checked mode" {
        InModuleScope Microsoft.AVS.CDR {
            Mock Get-PSResourcesPinned {
                @(
                    [pscustomobject]@{
                        Name = 'LoadedModuleFixture'
                        Version = '1.2.3'
                        InstalledLocation = '/verified/LoadedModuleFixture/1.2.3'
                        Dependencies = @()
                    }
                )
            }
            Mock Assert-CdrResolvedModuleSignatures { }
            Mock Get-Module {
                [pscustomobject]@{
                    Name = 'LoadedModuleFixture'
                    Version = [version]'1.2.3'
                    ModuleBase = '/different/path/LoadedModuleFixture/1.2.3'
                }
            }
            Mock Import-Module { throw 'should not import over a mismatched loaded module' }

            {
                Import-ModulePinned -Name 'LoadedModuleFixture' -RequiredVersion '1.2.3' -AuthenticodeCheck
            } | Should -Throw '*LoadedModuleFixture*1.2.3*/different/path/LoadedModuleFixture/1.2.3*/verified/LoadedModuleFixture/1.2.3*fresh PowerShell process*'

            Should -Invoke Assert-CdrResolvedModuleSignatures -Times 1 -Exactly
            Should -Invoke Import-Module -Times 0 -Exactly
        }
    }

    It "imports stable checked modules by exact manifest path without RequiredVersion" {
        $stableModule = New-CdrFixtureModule -ModulesRoot (Join-Path $TestDrive 'stable-modules') `
            -Name 'VerifiedStableModule' -Version '1.2.3'

        InModuleScope Microsoft.AVS.CDR -ArgumentList $stableModule {
            param($stableModule)

            $installedLocation = $stableModule.ModuleVersionPath
            $expectedManifestPath = $stableModule.ManifestPath

            Mock Get-PSResourcesPinned {
                @(
                    [pscustomobject]@{
                        Name = 'VerifiedStableModule'
                        Version = '1.2.3'
                        InstalledLocation = $installedLocation
                        Dependencies = @()
                    }
                )
            }
            Mock Assert-CdrResolvedModuleSignatures { }
            Mock Get-Module { @() }
            Mock Import-Module {
                [pscustomobject]@{
                    Name = 'VerifiedStableModule'
                    Version = [version]'1.2.3'
                    ModuleBase = $installedLocation
                }
            }

            $result = Import-ModulePinned -Name 'VerifiedStableModule' -RequiredVersion '1.2.3' -AuthenticodeCheck -PassThru

            $result.ModuleBase | Should -BeExactly $installedLocation
            Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter {
                $Name -eq $expectedManifestPath -and
                $ErrorAction -eq 'Stop' -and
                $Global -eq $true -and
                $DisableNameChecking -eq $true -and
                -not $RequiredVersion
            }
        }
    }

    It "imports prerelease checked dependency graphs by exact manifest path" {
        $manifestPath = Join-Path $TestDrive 'CheckedPrereleaseRoot.psd1'
        $prereleaseModule = New-CdrFixtureModule -ModulesRoot (Join-Path $TestDrive 'prerelease-modules') `
            -Name 'VerifiedPrereleaseModule' -Version '2.0.0' -Prerelease 'preview.1'
@"
@{
    RootModule = 'CheckedPrereleaseRoot.psm1'
    ModuleVersion = '1.0.0'
    RequiredModules = @(
        @{ ModuleName = 'VerifiedPrereleaseModule'; RequiredVersion = '2.0.0-preview.1' }
    )
}
"@ | Set-Content -LiteralPath $manifestPath

        InModuleScope Microsoft.AVS.CDR -ArgumentList $manifestPath, $prereleaseModule {
            param($manifestPath, $prereleaseModule)

            $installedLocation = $prereleaseModule.ModuleVersionPath
            $expectedManifestPath = $prereleaseModule.ManifestPath

            Mock Assert-CdrFileSignature { }
            Mock Build-InstalledDependencyGraph {
                param([string]$ModuleName, [string]$ModuleVersion, [hashtable]$Graph)
                $moduleKey = "$ModuleName@$ModuleVersion"
                $Graph[$moduleKey] = [DependencyGraphNode]::new(
                    $ModuleName,
                    $ModuleVersion,
                    [System.Collections.ArrayList]@(),
                    $false,
                    $null,
                    $installedLocation
                )
                $moduleKey
            }
            Mock Resolve-DiamondDependencies { @{} }
            Mock Resolve-GraphRootKey { $RootKeys }
            Mock Get-TopologicalOrder { $RootKeys }
            Mock Assert-CdrResolvedModuleSignatures { }
            Mock Get-Module { @() }
            Mock Import-Module {
                [pscustomobject]@{
                    Name = 'VerifiedPrereleaseModule'
                    Version = [version]'2.0.0'
                    ModuleBase = $installedLocation
                }
            }

            $result = Import-PSResourceDependencies -ManifestPath $manifestPath -AuthenticodeCheck -PassThru

            $result | Should -HaveCount 1
            $result[0].ModuleBase | Should -BeExactly $installedLocation
            Should -Invoke Assert-CdrFileSignature -Times 1 -Exactly -ParameterFilter {
                $LiteralPath -eq $manifestPath
            }
            Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter {
                $Name -eq $expectedManifestPath -and
                $ErrorAction -eq 'Stop' -and
                $Global -eq $true -and
                $DisableNameChecking -eq $true -and
                -not $RequiredVersion
            }
        }
    }

    It "uses exact manifest paths in checked mode even when another module-path entry shadows the name" {
        $verifiedRoot = Join-Path $TestDrive 'verified-modules'
        $shadowRoot = Join-Path $TestDrive 'shadow-modules'
        $verifiedModule = New-CdrFixtureModule -ModulesRoot $verifiedRoot `
            -Name 'ShadowedCheckedModule' -Version '3.4.5' `
            -SentinelVariableName 'CdrImportSentinel' -SentinelValue 'verified'
        $shadowModule = New-CdrFixtureModule -ModulesRoot $shadowRoot `
            -Name 'ShadowedCheckedModule' -Version '3.4.5' `
            -SentinelVariableName 'CdrImportSentinel' -SentinelValue 'shadow'

        $env:PSModulePath = "$shadowRoot$([IO.Path]::PathSeparator)$verifiedRoot$([IO.Path]::PathSeparator)$script:originalPSModulePath"

        InModuleScope Microsoft.AVS.CDR -ArgumentList $verifiedModule {
            param($verifiedModule)

            Mock Get-PSResourcesPinned {
                @(
                    [pscustomobject]@{
                        Name = $verifiedModule.Name
                        Version = $verifiedModule.Version
                        InstalledLocation = $verifiedModule.ModuleVersionPath
                        Dependencies = @()
                    }
                )
            }
            Mock Assert-CdrResolvedModuleSignatures { }

            $result = Import-ModulePinned -Name $verifiedModule.Name `
                -RequiredVersion $verifiedModule.Version -AuthenticodeCheck -Force -PassThru

            $result.ModuleBase | Should -BeExactly $verifiedModule.ModuleVersionPath
        }

        $global:CdrImportSentinel | Should -Be @('verified')
        Get-Module -Name 'ShadowedCheckedModule' | Should -Not -BeNullOrEmpty
        (Get-Module -Name 'ShadowedCheckedModule').ModuleBase | Should -BeExactly $verifiedModule.ModuleVersionPath
        Test-Path -LiteralPath $shadowModule.ModuleVersionPath | Should -BeTrue
    }

    It "forces a checked re-import by exact manifest path" {
        $forceModule = New-CdrFixtureModule -ModulesRoot (Join-Path $TestDrive 'force-modules') `
            -Name 'LoadedDependencyFixture' -Version '1.2.3'

        InModuleScope Microsoft.AVS.CDR -ArgumentList $forceModule {
            param($forceModule)

            $installedLocation = $forceModule.ModuleVersionPath
            $expectedManifestPath = $forceModule.ManifestPath

            Mock Get-PSResourcesPinned {
                @(
                    [pscustomobject]@{
                        Name = 'LoadedDependencyFixture'
                        Version = '1.2.3'
                        InstalledLocation = $installedLocation
                        Dependencies = @()
                    }
                )
            }
            Mock Assert-CdrResolvedModuleSignatures { }
            Mock Get-Module {
                [pscustomobject]@{
                    Name = 'LoadedDependencyFixture'
                    Version = [version]'1.2.3'
                    ModuleBase = $installedLocation
                }
            }
            Mock Import-Module {
                [pscustomobject]@{
                    Name = 'LoadedDependencyFixture'
                    Version = [version]'1.2.3'
                    ModuleBase = $installedLocation
                }
            }

            $result = Import-ModulePinned -Name 'LoadedDependencyFixture' -RequiredVersion '1.2.3' `
                -AuthenticodeCheck -Force -PassThru

            $result.ModuleBase | Should -BeExactly $installedLocation
            Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter {
                $Name -eq $expectedManifestPath -and $Force -eq $true
            }
        }
    }
}

Describe "OpenAuthenticode real signature fixtures" {
    It "verifies a signed PowerShell script with a disposable trust store" {
        $certificate = New-TestCertificate
        $trustStore = New-TrustStore -Certificate $certificate
        $scriptPath = Join-Path $TestDrive 'Signed.ps1'

        New-SignedPowerShellFile -LiteralPath $scriptPath -Certificate $certificate -Content "Write-Output 'signed'"

        $signature = @(Get-OpenAuthenticodeSignature -LiteralPath $scriptPath -TrustStore $trustStore -ErrorAction Stop)

        $signature.Count | Should -Be 1
    }

    It "verifies a signed PowerShell formatting XML file" {
        $certificate = New-TestCertificate
        $trustStore = New-TrustStore -Certificate $certificate
        $xmlPath = Join-Path $TestDrive 'Fixture.ps1xml'

        New-SignedPowerShellFile -LiteralPath $xmlPath -Certificate $certificate -Content @'
<Configuration>
  <ViewDefinitions />
</Configuration>
'@

        $signature = @(Get-OpenAuthenticodeSignature -LiteralPath $xmlPath -TrustStore $trustStore -ErrorAction Stop)

        $signature.Count | Should -Be 1
    }

    It "verifies a signed PE assembly" {
        $certificate = New-TestCertificate
        $trustStore = New-TrustStore -Certificate $certificate
        $dllPath = Join-Path $TestDrive 'Fixture.dll'

        Add-Type -TypeDefinition 'public class FixtureAssembly { public static int Value => 1; }' `
            -OutputAssembly $dllPath -ErrorAction Stop
        Set-OpenAuthenticodeSignature -LiteralPath $dllPath -Certificate $certificate -ErrorAction Stop | Out-Null

        $signature = @(Get-OpenAuthenticodeSignature -LiteralPath $dllPath -TrustStore $trustStore -ErrorAction Stop)

        $signature.Count | Should -Be 1
    }

    It "rejects an unsigned file" {
        $scriptPath = Join-Path $TestDrive 'Unsigned.ps1'
        Set-Content -LiteralPath $scriptPath -Value "Write-Output 'unsigned'"

        {
            Get-OpenAuthenticodeSignature -LiteralPath $scriptPath -ErrorAction Stop | Out-Null
        } | Should -Throw '*does not contain an authenticode signature*'
    }

    It "rejects an untrusted self-signed signature without a trust override" {
        $certificate = New-TestCertificate
        $scriptPath = Join-Path $TestDrive 'Untrusted.ps1'

        New-SignedPowerShellFile -LiteralPath $scriptPath -Certificate $certificate -Content "Write-Output 'signed'"

        {
            Get-OpenAuthenticodeSignature -LiteralPath $scriptPath -ErrorAction Stop | Out-Null
        } | Should -Throw '*Certificate trust could not be established*'
    }

    It "rejects a tampered signed file even with the matching trust store" {
        $certificate = New-TestCertificate
        $trustStore = New-TrustStore -Certificate $certificate
        $scriptPath = Join-Path $TestDrive 'Tampered.ps1'

        New-SignedPowerShellFile -LiteralPath $scriptPath -Certificate $certificate -Content "Write-Output 'signed'"
        Add-Content -LiteralPath $scriptPath -Value "`n# tampered"

        {
            Get-OpenAuthenticodeSignature -LiteralPath $scriptPath -TrustStore $trustStore -ErrorAction Stop | Out-Null
        } | Should -Throw '*does not contain an authenticode signature*'
    }
}
