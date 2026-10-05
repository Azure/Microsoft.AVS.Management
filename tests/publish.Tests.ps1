BeforeAll {
    $publishScript = Join-Path $PSScriptRoot '../.build-tools/publish.ps1'
    $parseErrors = $null
    $publishAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $publishScript, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw ($parseErrors.Message -join [Environment]::NewLine)
    }

    # Load only the helper, without running the publishing script's side effects.
    $helper = $publishAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'New-PublishingSecureString'
    }, $false)
    if ($null -ne $helper) {
        . ([scriptblock]::Create($helper.Extent.Text))
    }
}

Describe 'Publishing token conversion' {
    It 'returns only a SecureString and preserves <Text> exactly' -TestCases @(
        @{ Text = 'test-token' }
        @{ Text = ' test.token+with/symbols= ' }
        @{ Text = 'test-$token;not-code' }
    ) {
        param($Text)
        $output = @(New-PublishingSecureString -Text $Text *>&1)

        $output.Count | Should -Be 1
        $output[0] | Should -BeOfType ([System.Security.SecureString])
        $credential = [PSCredential]::new('ONEBRANCH_TOKEN', $output[0])
        $credential.GetNetworkCredential().Password | Should -BeExactly $Text
    }

    It 'rejects empty or null token input' -TestCases @(
        @{ Text = '' }
        @{ Text = $null }
    ) {
        param($Text)
        { New-PublishingSecureString -Text $Text } |
            Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
    }

    It 'places the justified suppression on the helper, not the publishing script' {
        $attributes = (Get-Command New-PublishingSecureString).ScriptBlock.Attributes
        $suppression = @($attributes | Where-Object {
            $_ -is [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute]
        })

        $suppression.Count | Should -Be 1
        $suppression[0].Category | Should -BeExactly 'PSAvoidUsingConvertToSecureStringWithPlainText'
        $suppression[0].Justification | Should -Not -BeNullOrEmpty
        $publishAst.ParamBlock.Attributes.TypeName.FullName |
            Should -Not -Contain 'Diagnostics.CodeAnalysis.SuppressMessageAttribute'
    }
}
