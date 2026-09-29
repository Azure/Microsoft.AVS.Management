BeforeAll {
    $modulePath = Join-Path $PSScriptRoot ".." "Microsoft.AVS.CDR" "Microsoft.AVS.CDR.psd1"
    Import-Module $modulePath -Force
    Import-Module OpenAuthenticode -Force
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

Describe "OpenAuthenticode real signature fixtures" {
    BeforeAll {
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
    }

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
