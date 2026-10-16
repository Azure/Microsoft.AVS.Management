BeforeAll {
    $script:repoRoot = Split-Path $PSScriptRoot -Parent
    $script:cdrManifestPath = Join-Path $script:repoRoot 'Microsoft.AVS.CDR' 'Microsoft.AVS.CDR.psd1'
    $script:getRequiredModulesPath = Join-Path $script:repoRoot '.build-tools' 'getRequiredModules.ps1'
    $script:prevalidateModulesPath = Join-Path $script:repoRoot 'tests' 'prevalidateModules.ps1'

    $script:selectedOpenAuthenticodeVersion = '0.6.3'
    $script:supportedOpenAuthenticodeExtensions = @(
        '.ps1'
        '.psd1'
        '.psm1'
        '.psc1'
        '.ps1xml'
        '.dll'
        '.exe'
    )
}

Describe 'OpenAuthenticode release contract' {
    It 'records the selected published OpenAuthenticode version and supported extensions' {
        $script:selectedOpenAuthenticodeVersion | Should -Be '0.6.3'
        $script:supportedOpenAuthenticodeExtensions | Should -Be @(
            '.ps1'
            '.psd1'
            '.psm1'
            '.psc1'
            '.ps1xml'
            '.dll'
            '.exe'
        )
    }
}

Describe 'Microsoft.AVS.CDR manifest bootstrap contract' {
    BeforeAll {
        $script:cdrManifest = Import-PowerShellDataFile -Path $script:cdrManifestPath
    }

    It 'declares an exact RequiredModules entry for OpenAuthenticode' {
        $requiredModule = @($script:cdrManifest.RequiredModules | Where-Object {
            $_.ModuleName -eq 'OpenAuthenticode'
        })

        $requiredModule.Count | Should -Be 1
        $requiredModule[0].RequiredVersion | Should -Be $script:selectedOpenAuthenticodeVersion
        $requiredModule[0].ContainsKey('ModuleVersion') | Should -BeFalse
        $requiredModule[0].ContainsKey('MaximumVersion') | Should -BeFalse
    }
}

Describe '.build-tools/getRequiredModules.ps1 bootstrap sequencing' {
    BeforeAll {
        $script:getRequiredModulesContent = Get-Content -Path $script:getRequiredModulesPath -Raw
    }

    It 'restores OpenAuthenticode from the CDR manifest before importing source CDR' {
        $script:getRequiredModulesContent | Should -Match 'Import-PowerShellDataFile'
        $script:getRequiredModulesContent | Should -Match 'OpenAuthenticode'
        $script:getRequiredModulesContent | Should -Match 'RequiredModules'
        $script:getRequiredModulesContent | Should -Match 'RequiredVersion'
        $script:getRequiredModulesContent | Should -Not -Match [regex]::Escape($script:selectedOpenAuthenticodeVersion)

        $manifestImportIndex = $script:getRequiredModulesContent.IndexOf(
            'Import-PowerShellDataFile',
            [System.StringComparison]::OrdinalIgnoreCase)
        $openAuthenticodeIndex = $script:getRequiredModulesContent.IndexOf(
            'OpenAuthenticode',
            [System.StringComparison]::OrdinalIgnoreCase)
        $cdrImportIndex = $script:getRequiredModulesContent.IndexOf(
            'import-module $cdr',
            [System.StringComparison]::OrdinalIgnoreCase)

        $manifestImportIndex | Should -BeGreaterThan -1
        $openAuthenticodeIndex | Should -BeGreaterThan -1
        $cdrImportIndex | Should -BeGreaterThan -1
        $manifestImportIndex | Should -BeLessThan $cdrImportIndex
        $openAuthenticodeIndex | Should -BeLessThan $cdrImportIndex
    }
}

Describe 'tests/prevalidateModules.ps1 CDR test discovery' {
    BeforeAll {
        $script:prevalidateModulesContent = Get-Content -Path $script:prevalidateModulesPath -Raw
    }

    It 'includes the base CDR suite and CDR companion-suite wildcard in discovery' {
        $script:prevalidateModulesContent | Should -Match ([regex]::Escape('$moduleFolderName.Tests.ps1'))
        $script:prevalidateModulesContent | Should -Match ([regex]::Escape('Microsoft.AVS.CDR.*.Tests.ps1'))
    }

    It 'limits the wildcard discovery to CDR-specific suites rather than all *.Tests.ps1 files' {
        $script:prevalidateModulesContent | Should -Match ([regex]::Escape('Microsoft.AVS.CDR.*.Tests.ps1'))
        $script:prevalidateModulesContent | Should -Not -Match ([regex]::Escape("-Filter '*.Tests.ps1'"))
    }
}
