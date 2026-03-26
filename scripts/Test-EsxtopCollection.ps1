#Requires -Modules VCF.PowerCLI

<#
.SYNOPSIS
    Collects esxtop data via vCenter ServiceManager using raw SOAP requests.
    Bypasses both Get-View and WCF client bugs in VCF.PowerCLI 9.x.

.DESCRIPTION
    Based on William Lam's approach + Justin's corrections:
    1. QueryServiceList via raw SOAP to find the Esxtop service on the host
    2. ExecuteSimpleCommand("CounterInfo" | "FetchStats" | "FreeStats") via raw SOAP

    Single-host collection only (first connected host matching EsxiHostName). One CSV per run, no
    splitting. Sampling is limited to 30 seconds of spacing between snapshots —
    (Iterations - 1) * IntervalSeconds <= 30 — to avoid large payloads on customer vSAN datastores.

.EXAMPLE
    .\Test-EsxtopCollection.ps1 -VCenterServer "192.168.92.2" -ClusterName "Cluster-1" -EsxiHostName "esx01"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VCenterServer,
    [Parameter(Mandatory)][string]$ClusterName,
    [Parameter(Mandatory)][string]$EsxiHostName,
    [Parameter()][ValidateScript({ $_ -ge 1 })][int]$Iterations = 6,
    [Parameter()][ValidateRange(1, 30)][int]$IntervalSeconds = 5,
    [Parameter()][string]$OutFile
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [ValidateSet("Info","Warn","Error","OK")][string]$Level = "Info")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ Info = "Cyan"; Warn = "Yellow"; Error = "Red"; OK = "Green" }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Invoke-VCenterSoap {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SessionCookie,
        [Parameter(Mandatory)][string]$SoapBody
    )

    $envelope = @"
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Body>
$SoapBody
</soap:Body>
</soap:Envelope>
"@

    $uri = "https://$Server/sdk"
    $headers = @{
        "Content-Type" = "text/xml; charset=utf-8"
        "SOAPAction"   = "urn:vim25"
        "Cookie"       = "vmware_soap_session=$SessionCookie"
    }

    $resp = Invoke-WebRequest -Uri $uri -Method POST -Headers $headers -Body $envelope `
        -SkipCertificateCheck -UseBasicParsing -ErrorAction Stop

    return [xml]$resp.Content
}

function Get-EsxtopServiceMoRef {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SessionCookie,
        [Parameter(Mandatory)][string]$SvcMgrType,
        [Parameter(Mandatory)][string]$SvcMgrValue,
        [Parameter(Mandatory)][string]$HostName
    )

    $locationString = "vmware.host." + $HostName

    $body = @"
<QueryServiceList xmlns="urn:vim25">
  <_this type="$SvcMgrType">$SvcMgrValue</_this>
  <location>$locationString</location>
</QueryServiceList>
"@

    $xml = Invoke-VCenterSoap -Server $Server -SessionCookie $SessionCookie -SoapBody $body

    $services = $xml.Envelope.Body.QueryServiceListResponse.returnval
    if (-not $services) {
        throw "QueryServiceList returned no services for location '$locationString'."
    }

    $serviceNames = @()
    foreach ($svc in $services) {
        $name = $svc.serviceName
        $serviceNames += $name
        Write-Host "  Service: $name" -ForegroundColor DarkGray
        if ($name -eq "Esxtop") {
            $ref = $svc.service
            return @{
                Type  = $ref.type
                Value = $ref.'#text'
            }
        }
    }

    throw "Esxtop service not found on host '$HostName'. Available: $($serviceNames -join ', ')"
}

function Invoke-EsxtopCommand {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SessionCookie,
        [Parameter(Mandatory)][string]$SvcType,
        [Parameter(Mandatory)][string]$SvcValue,
        [Parameter(Mandatory)][ValidateSet("CounterInfo","FetchStats","FreeStats")][string]$Command
    )

    $body = @"
<ExecuteSimpleCommand xmlns="urn:vim25">
  <_this type="$SvcType">$SvcValue</_this>
  <arguments>$Command</arguments>
</ExecuteSimpleCommand>
"@

    $xml = Invoke-VCenterSoap -Server $Server -SessionCookie $SessionCookie -SoapBody $body

    $result = $xml.Envelope.Body.ExecuteSimpleCommandResponse.returnval
    return $result
}

$samplingSpanSec = [Math]::Max(0, $Iterations - 1) * $IntervalSeconds
if ($samplingSpanSec -gt 30) {
    throw "Esxtop sampling is limited to 30 seconds between first and last sample: (Iterations-1)*IntervalSeconds must be <= 30. Current: ${samplingSpanSec}s (Iterations=$Iterations, IntervalSeconds=$IntervalSeconds)."
}

# --- Connect to vCenter ---
try {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
    Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false | Out-Null

    $secPw = ConvertTo-SecureString '99pxX7^Lo1)v' -AsPlainText -Force
    $cred = [pscredential]::new('administrator@vsphere.local', $secPw)

    Write-Log "Connecting to vCenter $VCenterServer..."
    $vc = Connect-VIServer -Server $VCenterServer -Credential $cred -Force
    Write-Log "Connected: $($vc.Name) v$($vc.Version)" "OK"
}
catch {
    Write-Log "Failed to connect to vCenter: $($_.Exception.Message)" "Error"
    throw
}

try {
    # --- Get the session cookie ---
    $sessionCookie = $null
    if ($vc.SessionSecret) {
        $sessionCookie = $vc.SessionSecret
        Write-Log "Got session from SessionSecret" "OK"
    }
    if (-not $sessionCookie) {
        try {
            $cookieJar = $vc.ExtensionData.Client.VimService.CookieContainer
            if ($cookieJar) {
                $cookies = $cookieJar.GetCookies([Uri]"https://$VCenterServer/sdk")
                $soapCookie = $cookies | Where-Object { $_.Name -eq "vmware_soap_session" }
                if ($soapCookie) { $sessionCookie = $soapCookie.Value; Write-Log "Got session from CookieContainer" "OK" }
            }
        } catch { Write-Log "CookieContainer failed: $($_.Exception.Message)" "Warn" }
    }
    if (-not $sessionCookie) {
        Write-Log "Logging in via raw SOAP..." "Info"
        $loginBody = @"
<Login xmlns="urn:vim25">
  <_this type="SessionManager">SessionManager</_this>
  <userName>administrator@vsphere.local</userName>
  <password>99pxX7^Lo1)v</password>
</Login>
"@
        $loginEnvelope = "<?xml version=`"1.0`"?><soap:Envelope xmlns:soap=`"http://schemas.xmlsoap.org/soap/envelope/`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`" xmlns:xsd=`"http://www.w3.org/2001/XMLSchema`"><soap:Body>$loginBody</soap:Body></soap:Envelope>"
        $loginResp = Invoke-WebRequest -Uri "https://$VCenterServer/sdk" -Method POST `
            -Headers @{ "Content-Type" = "text/xml; charset=utf-8"; "SOAPAction" = "urn:vim25" } `
            -Body $loginEnvelope -SkipCertificateCheck -UseBasicParsing -ErrorAction Stop
        $setCookie = $loginResp.Headers["Set-Cookie"]
        if ($setCookie) {
            $match = [regex]::Match(($setCookie -join ';'), 'vmware_soap_session=([^;]+)')
            if ($match.Success) { $sessionCookie = $match.Groups[1].Value; Write-Log "Got session from raw SOAP Login" "OK" }
        }
    }
    if (-not $sessionCookie) { throw "Could not obtain SOAP session cookie." }

    # --- Get ServiceManager MoRef ---
    $svcMgrRef = $vc.ExtensionData.Content.ServiceManager
    Write-Log "ServiceManager: Type=$($svcMgrRef.Type) Value=$($svcMgrRef.Value)" "OK"

    # --- Find ESXi host ---
    $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    Write-Log "Found cluster: $($cluster.Name)" "OK"

    $vmHost = $cluster | Get-VMHost |
        Where-Object { $_.Name -like "$EsxiHostName*" -and $_.ConnectionState -eq 'Connected' } |
        Select-Object -First 1

    if ($null -eq $vmHost) {
        throw "No connected ESXi host matching '$EsxiHostName' found in cluster '$ClusterName'."
    }
    Write-Log "Target host: $($vmHost.Name)" "OK"

    # --- Find Esxtop service via SOAP ---
    Write-Log "Querying services on host..."
    $esxtopRef = Get-EsxtopServiceMoRef -Server $VCenterServer -SessionCookie $sessionCookie `
        -SvcMgrType $svcMgrRef.Type -SvcMgrValue $svcMgrRef.Value -HostName $vmHost.Name
    Write-Log "Esxtop service: Type=$($esxtopRef.Type) Value=$($esxtopRef.Value)" "OK"

    # --- Step 1: CounterInfo ---
    Write-Log "Fetching CounterInfo..."
    $counterInfo = Invoke-EsxtopCommand -Server $VCenterServer -SessionCookie $sessionCookie `
        -SvcType $esxtopRef.Type -SvcValue $esxtopRef.Value -Command "CounterInfo"
    Write-Log "CounterInfo returned $($counterInfo.Length) chars" "OK"

    # --- Step 2: FetchStats loop - stream to single CSV file (30s max spacing; no splitting) ---
    Write-Log "Collecting $Iterations samples (interval=${IntervalSeconds}s, ${samplingSpanSec}s between first and last sample)..."

    $hostShort = ($vmHost.Name -split '\.')[0]
    $csvFile = ".\esxtop_${hostShort}.0.csv"
    '"Timestamp","SampleNumber","RawData"' | Out-File -FilePath $csvFile -Encoding UTF8
    $totalBytes = 0

    for ($i = 1; $i -le $Iterations; $i++) {
        Write-Log "Sample $i/$Iterations - Fetching..." "Info"
        $sampleStart = Get-Date

        $stats = Invoke-EsxtopCommand -Server $VCenterServer -SessionCookie $sessionCookie `
            -SvcType $esxtopRef.Type -SvcValue $esxtopRef.Value -Command "FetchStats"

        $fetchMs = [math]::Round(((Get-Date) - $sampleStart).TotalMilliseconds)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $escaped = $stats -replace '"', '""'
        $csvRow = '"' + $timestamp + '",' + $i + ',"' + $escaped + '"'
        $csvRow | Out-File -FilePath $csvFile -Encoding UTF8 -Append
        $totalBytes += $stats.Length

        $fileSizeMB = [math]::Round((Get-Item $csvFile).Length / 1MB, 1)
        $remainSec = ($Iterations - $i) * $IntervalSeconds
        Write-Log "Sample $i/$Iterations - Done (${fetchMs}ms, file ${fileSizeMB}MB, ${remainSec}s left)" "OK"

        if ($i -lt $Iterations) {
            Write-Log "Waiting ${IntervalSeconds}s before next sample..." "Info"
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    # --- Step 3: FreeStats ---
    Write-Log "Releasing stats..."
    try {
        Invoke-EsxtopCommand -Server $VCenterServer -SessionCookie $sessionCookie `
            -SvcType $esxtopRef.Type -SvcValue $esxtopRef.Value -Command "FreeStats" | Out-Null
        Write-Log "Stats released" "OK"
    }
    catch {
        Write-Log "FreeStats warning: $($_.Exception.Message)" "Warn"
    }

    $finalMB = [math]::Round((Get-Item $csvFile).Length / 1MB, 1)
    Write-Log "CSV saved: $csvFile (${finalMB}MB)" "OK"

    # --- Upload to vSAN datastore with rotation (keep last 3) ---
    Write-Log "Uploading to vSAN datastore (rotating, keep last 3)..."

    $datastore = Get-Datastore -RelatedObject $cluster -ErrorAction SilentlyContinue |
        Where-Object { $_.Type -eq 'vsan' -or $_.Name -like '*vsan*' -or $_.Name -like '*vsanDatastore*' } |
        Select-Object -First 1

    if (-not $datastore) {
        $datastore = Get-Datastore -RelatedObject $cluster -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if ($datastore) {
        $dsPath = "vmstore:\$($datastore.Datacenter)\$($datastore.Name)"
        $destFolder = "$dsPath\esxtop_output"

        if (-not (Test-Path $destFolder -ErrorAction SilentlyContinue)) {
            New-Item -Path $destFolder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
        }

        $dsFile = "esxtop_${hostShort}"
        $slot2 = "$destFolder\${dsFile}.2.csv"
        $slot1 = "$destFolder\${dsFile}.1.csv"
        $slot0 = "$destFolder\${dsFile}.0.csv"

        # Rotate: rm .2, .1->.2, .0->.1, write new to .0
        if (Test-Path $slot2 -ErrorAction SilentlyContinue) {
            Remove-Item $slot2 -Force -ErrorAction SilentlyContinue
            Write-Log "Removed oldest: ${dsFile}.2.csv" "Info"
        }
        if (Test-Path $slot1 -ErrorAction SilentlyContinue) {
            Copy-DatastoreItem -Item $slot1 -Destination $slot2 -Force -ErrorAction SilentlyContinue
            Remove-Item $slot1 -Force -ErrorAction SilentlyContinue
            Write-Log "Rotated: ${dsFile}.1.csv -> .2.csv" "Info"
        }
        if (Test-Path $slot0 -ErrorAction SilentlyContinue) {
            Copy-DatastoreItem -Item $slot0 -Destination $slot1 -Force -ErrorAction SilentlyContinue
            Remove-Item $slot0 -Force -ErrorAction SilentlyContinue
            Write-Log "Rotated: ${dsFile}.0.csv -> .1.csv" "Info"
        }

        try {
            Copy-DatastoreItem -Item $csvFile -Destination $slot0 -Force -ErrorAction Stop
            Write-Log "Saved: [$($datastore.Name)] esxtop_output/${dsFile}.0.csv" "OK"
        }
        catch {
            Write-Log "Upload failed: $($_.Exception.Message)" "Warn"
        }
    }
    else {
        Write-Log "No datastore found on cluster '$ClusterName' - skipping upload" "Warn"
    }

    Write-Host ""
    Write-Log "Collection complete. $Iterations samples from $($vmHost.Name)." "OK"
    Write-Log "Local: $csvFile" "OK"
    if ($datastore) {
        Write-Log "Datastore: [$($datastore.Name)] esxtop_output/${dsFile}.0.csv (newest)" "OK"
        Write-Log "  .0.csv = this run, .1.csv = previous, .2.csv = oldest" "Info"
    }
}
catch {
    Write-Log "$($_.Exception.Message)" "Error"
    if ($_.Exception.InnerException) {
        Write-Log "InnerException: $($_.Exception.InnerException.Message)" "Error"
    }
    throw
}
finally {
    if ($global:DefaultVIServer) {
        Disconnect-VIServer -Server $global:DefaultVIServer -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Disconnected from vCenter" "Info"
    }
}
