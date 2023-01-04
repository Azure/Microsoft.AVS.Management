<#
    .Synopsis
    Get the authorization token found in the response headers under the name of 'x-hm-authorization'

    .Parameter Credential
    Specifies a PSCredential object that contains credentials for authenticating with the server.
    For more information about the server authentication logic of PowerCLI, run "help about_server_authentication".

    .Parameter HcxServer
    Specifies the IP or DNS addresses of the HCX servers to connect to.

    .Example
    Get-AuthorizationToken -Credential {UserCreds} -HcxServer "10.40.0.9"
#>
function Get-AuthorizationToken {
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Credential for the VCSA API")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Server Name')]
        [ValidateNotNull()]
        [string]
        $HcxServer
    )

    $networkCred = (New-Object System.Management.Automation.PSCredential $Credential.UserName, $Credential.Password).GetNetworkCredential()
    $JsonBody = @{'username' = $networkCred.UserName; 'password' = $networkCred.Password } | ConvertTo-Json

    Write-Host "Create Hybridity Session:"
    $elapsed = Measure-Command -Expression `
    { Invoke-RestMethod -Method 'POST' `
            -Uri https://${HcxServer}/hybridity/api/sessions `
            -ContentType 'application/json' -Body $JsonBody `
            -Verbose -SkipCertificateCheck `
            -ResponseHeadersVariable SessionHeaders -ErrorAction Stop }

    Write-Host "Created Hybridity Session: elapsed=${elapsed}"
    return $SessionHeaders['x-hm-authorization']
}

<#
    .Synopsis
    Get and return Hcx Metadata Blob

    .Parameter XHmAuthorization
    Valid authorization token obtained by performing a POST to https://<HCX-Server>/hybridity/api/sessions

    .Parameter HcxServer
    Specifies the IP or DNS addresses of the HCX servers you want to connect to.

    .Example
    Get-HcxMetaData -XHmAuthorization <authToken> -HcxServer "10.40.0.9"
#>
function Get-HcxMetaData {
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Hybridity Session')]
        [ValidateNotNull()]
        [string]
        $XHmAuthorization,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'HCX Server Name')]
        [ValidateNotNull()]
        [string]
        $HcxServer
    )

    $headers = @{
        "x-hm-authorization"="$XHmAuthorization"
        "Content-Type"="application/json"
        "Accept"="application/json"
    }
    $body = "{filter={},options={}}"

    Write-Host "Retrieving HCX Manager Meta Data"
    $elapsed = Measure-Command -Expression { $response = Invoke-RestMethod -Uri "https://${HcxServer}/hybridity/api/metainfo/context/support" -Method 'GET' -Headers $headers -Body $body -Verbose -SkipCertificateCheck -ErrorAction Stop }

    if ($response.success -eq 'True') {
        Write-Host "Retrieved HCX Manager Meta Data: elapsed=${elapsed}"
        return $response.data.localEndpoints
    }

    throw "Unable To Retrieve HCX Manager Meta Data"
}