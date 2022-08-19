#region - utilities

function Get-RandomSeed() {
    # Helper Function: generate random integer as a seed for Get-Random
    # from: https://the.powershell.zone/2009/05/20/truly-random-numbers-and-passwords-in-powershell/

    $randomBytes = New-Object -TypeName 'System.Byte[]' 64
    [System.Security.Cryptography.RNGCryptoServiceProvider]$Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
    $Random.GetBytes($randomBytes)
    [BitConverter]::ToInt32($randomBytes, 0)
}

function Get-RandomSymbol() {
    # Helper function: Generate a random printable ascii symbol
    # to get decimal values of ascii characters see: https://https://www.techonthenet.com/ascii/chart.php/
    param(
        $symbolExcl = @(32, 34, 39, 40, 41, 47, 60, 62, 92, 215),
        [switch]$allSymbols,
        [switch]$accentedLetters
    )

    $asciiDecs = 32..47 + 58..64

    if ($allSymbols) { $asciiDecs += 91..96 + 123..126 }
    elseif ($accentedLetters) { $asciiDecs += 192..255 }
    else { $asciiDecs = $asciiDecs | Where-Object { $_ -notin $symbolExcl } }

    $asciiDecs | 
    Get-Random -Count 1 -SetSeed $(Get-RandomSeed) | ForEach-Object { [char]$_ }
}

Function Format-FileSize() {
    # Helper function: convert bytes to human readable file sizes
    # inspired by: du -h

    Param ([parameter(ValueFromPipeline)][int64]$size)

    If ($size -gt 1TB) { [string]::Format('{0:0.00} TB', $size / 1TB) }
    ElseIf ($size -gt 1GB) { [string]::Format('{0:0.00} GB', $size / 1GB) }
    ElseIf ($size -gt 1MB) { [string]::Format('{0:0.0} MB', $size / 1MB) }
    ElseIf ($size -gt 1KB) { [string]::Format('{0:0} KB', $size / 1KB) }
    Else { [string]::Format('{0:0} B', $size) }
}

function Measure-DirectorySize() {
    # Helper function: Returns the size of a directory's contents in bytes

    param($path)

    $(Get-Item $path | 
        Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue -Include * -File | 
        Measure-Object -Property length -Sum).Sum  
} 

function Get-RestError() {
    # Helper function: parses the HTTP status code from a REST response object 
    # e.g.Invoke-WebRequest / Invoke-RestMethod

    param($response)

    [pscustomobject][ordered]@{
        message           = $($_.Exception.message )       
        statusCode        = $($_.Exception.Response.StatusCode.value__ )
        statusDescription = $($_.Exception.Response.StatusDescription)
        uri               = $($_.Exception.Response.ResponseUri)
    }
}

function Get-HostsFile() {
    param([string]$hostfile = "$env:windir\System32\drivers\etc\hosts")

    Get-Content -Path $hostfile
}

function Get-IdleTime() {
    [PInvoke.Win32.UserInput]::IdleTime
}

function Measure-LineCount() {
    # Helper function: gets line count for all files in a directory
    # supports extension filtering, useful for getting lines of code in a project

    param($diretory, $ext)

    Get-ChildItem "$diretory\*.$ext" -Recurse | ForEach-Object { 
        [pscustomobject]@{ 
            'directory' = Split-Path $_
            'file'      = Split-Path -Leaf $_
            'lines'     = $(Get-Content $_ | Measure-Object).Count
        }
    }
}

#endregion

#region - IP conversion functions

function Convert-IpToBinary() {
    # Helper Function: converts an IP in standard dotted decimal notation to binary

    param($ip)

    $NetworkIP = ([System.Net.IPAddress]$ip).GetAddressBytes()
    [Array]::Reverse($NetworkIP)
    ([System.Net.IPAddress]($NetworkIP -join '.')).Address
}

function Convert-BinaryIpToDottedDecimal() {
    # Helper Function: converts a binary ip back to standard dotted decimal notation

    param($ip)

    if (($ip.Gettype()).Name -ine 'double') {
        $ip = [Convert]::ToDouble($ip)
    }
    $([System.Net.IPAddress]$ip).IPAddressToString
}

function Convert-SubnetMaskToCidr() {
    # Helper function: converts a subnet mask to cidr (e.g. 255.255.255.0 to 24)

    param($subnetMask)

    # split subnetmask into octets
    $octets = $subnetMask.ToString().Split('.') |
    ForEach-Object -Process { [Convert]::ToString($_, 2) }
        
    # concatentate octets and count
    (($Octets -join '').TrimEnd('0')).length  
}

function Convert-CidrToSubnetMask() {
    # Helper function: converts a cidr mask to subnet mask (e.g. 24 to 255.255.255.0)

    param($cidr)

    $ipv4Max = [Math]::Pow(2, 32)

    # convert subnetmask to cidr using bit-wise shift
    $([ipaddress]([double]$ipv4Max - (1 -shl 32 - $cidr) ) ).IPAddressToString
}

function Test-IpInSubnet() {
    # Helper function: checks if an IP address is in a subnet specified in cidr notation
    # uses binary ANDing for the maths

    param (
        [System.Net.IPAddress]$ip, 
        [System.Net.IPAddress]$subnet, [int]$cidr
    ) 
    
    # convert cidr to netmask
    $SubnetMask = [ipaddress]( [math]::Pow(2, 32) - [math]::Pow(2, 32 - $cidr) ) 
    
    # user binary ANDing to check if IP is in specified subnet
    $Subnet.Address -eq ($ip.Address -band $SubnetMask.Address)
}

Function Get-IPV4Range () {
    # Helper function: get the first and last IP address in a subnet given in cidr notation
    # use the -usableIPs switch to just get the number of IPs

    param($network, $cidr, [switch]$usableIPs)

    $networkBinary = Convert-IpToBinary($network)
    
    # skip network ip, get first usable IP
    $firstIP = Convert-BinaryIpToDottedDecimal($networkBinary + 1)

    # skip network and boardcast addresses
    $numUsableIPs = ([System.Math]::Pow(2, 32 - $cidr) - 2)
    $lastIP = Convert-BinaryIpToDottedDecimal($networkBinary + $numUsableIPs)

    if ($usableIPs) { $numUsableIPs }
    else { ($firstIP, $lastIP) }
}

function Find-IP() {
    # Helper function: geolocate an IP address

    param($ip)

    if ($ip) { $url = "http://ip-api.com/json/$ip" }
    else { $url = 'http://ip-api.com/json/' }
    
    try { Invoke-WebRequest $url -UseBasicParsing | ConvertFrom-Json }
    catch { Write-Warning $_ }
}

#endregion

#region - Telnet

<# 
Heavily Adapted From: 
https://gsexdev.blogspot.com/2006/09/doing-smtp-telnet-test-with-powershell.html
http://www.leeholmes.com/blog/2006/08/30/replacing-telnet-exe-now-removed-from-vista/
#>

function Read-Stream {
    # Helper Function: Read telnet responses from raw TCP stream data

    param($verbose = $false)

    try {
        while ($global:stream.DataAvailable) {  
            $read = $global:stream.Read($global:buffer, 0, 1024)    
            $log = ($global:encoding.GetString($global:buffer, 0, $read))
            $log.Split("`n")
        }
    }
    catch { Write-Warning $_ }
}

function Connect-Telnet() {
    # Helper function: Setup stream socket

    param($remoteHost, $port)

    try {
        $global:socket = New-Object System.Net.Sockets.TcpClient($remoteHost, $port)
        $global:stream = $socket.GetStream() 
        $global:writer = New-Object System.IO.StreamWriter($stream) 
        $global:buffer = New-Object System.Byte[] 1024 
        $global:encoding = New-Object System.Text.AsciiEncoding
    }
    catch { Write-Warning $_ }
}

function Send-TelnetCommand() {
    # Helper function: send commands using stream socket, inspired by telnet

    param($command, $verbose = $false, $echo = $false, 
        $waitTime = 1000, $color = 'Green')

    try {
        if ($echo) { Write-Host -ForegroundColor $color $command }

        $global:writer.WriteLine($command)
        $global:writer.Flush()

        Start-Sleep -m $waitTime # in milliseconds
        if ($verbose) { Read-Stream }
    }
    catch { Write-Warning $_ }
}

function Disconnect-Telnet() {
    # Helper function: Clean up TCP socket

    if ($global:socket.Connected) {
        $global:writer.Close() 
        $global:stream.Close()
    }
}

function Get-WebServer() {
    # Helper function: use Send-TelnetCommand to test HTTP similar to Telnet

    param($remotehost, $port)

    Connect-Telnet -remoteHost $remotehost -port $port
    $(Send-TelnetCommand -command 'HEAD /index.html HTTP/1.1' -verbose $true -echo $true -waitTime 100)
    $(Send-TelnetCommand -command "Host: $remotehost" -verbose $true -echo $true -waitTime 100)
    
    # HTTP requires 2 blank lines
    $(Send-TelnetCommand -command "`r`n`r`n" -verbose $true -echo $true)
    Disconnect-Telnet
}

#endregion

#region - Certificates

function Unblock-InvalidCertificates() {
    # Helper function: Allow Invoke-WebRequest to ignore invalide SSL certificates

    # inspired by: curl -k
    # adapted from: https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error #>

    param ()

    if (-not ('TrustAllCertsPolicy' -as [type])) {
        Add-Type '
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                    return true;
                }
            }
        '

        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}

function Get-CertificateThumbprint() {
    # Helper function: Used to check if an existing certificate matches against a known list of in use thumbprints

    param(
        $object, 
        $parameters = ('startdate', 'enddate', 'thumbprint', 'usage', 'keyid')
    )
    
    if ($object.value) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import([System.Text.Encoding]::UTF8.GetBytes($object.value))
        $_ | Add-Member -MemberType NoteProperty -Name Thumbprint -Value $($cert.Thumbprint) -Force
        $_ | Select-Object $parameters
    }
}

function Get-SslProtocols() {
    # Helper function: Get protocols that have been explicitly enabled or disabled

    $SChannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' 
    
    ('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') | 
    ForEach-Object {
        Get-ItemProperty -Path "$($SChannel)\$_\Server" -Name Enabled -ErrorAction SilentlyContinue | 
        Select-Object pschildname, enabled, 
        @{n = 'Protocol'; e = { $($_.psparentpath | Split-Path -Leaf 2>$null) } 
        }

        Get-ItemProperty -Path "$($SChannel)\$_\Client" -Name Enabled -ErrorAction SilentlyContinue | 
        Select-Object pschildname, enabled, 
        @{ n = 'Protocol'; e = { $($_.psparentpath | Split-Path -Leaf 2>$null) } 
        }
    }
}

function Get-CipherSuites() {
    # Helper function: Get cipher suites that have been explicitly enabled or disabled

    $SChannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' 
    $insecureCiphers = @(
        'DES 56/56', 'NULL', 'RC2 128/128', 'RC2 40/128', 'RC2 56/128', 
        'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'Triple DES 168'
    )

    $insecureCiphers | ForEach-Object {
        $suite = $_
        Get-ItemProperty -Path "$($SChannel)\$_" `
            -Name Enabled `
            -ErrorAction SilentlyContinue | 
        Select-Object @{n = 'Suite'; e = { $suite } }, enabled
    }
}

function Find-PublicCertificates() {
    # Helper function: query crt.sh API for all certificates matching a query
    # see also: https://en.wikipedia.org/wiki/Certificate_Transparency

    param($query)

    Add-Type -AssemblyName System.Web
    $query = [System.Web.HttpUtility]::Urlencode($query)
    $url = "https://crt.sh/?q=%.$query&output=json"

    $response = Invoke-WebRequest -Uri $url -UseBasicParsing
    $results = $response.content | ConvertFrom-Json 
    
    $results | Sort-Object serial_number -Unique | 
    Select-Object common_name, name_value, not_before, not_after |
    Sort-Object not_after -Descending
} 

#endregion

#region - URLS

function ConvertFrom-EncodedUrl() {
    # Helper function: decode a html-encoded url

    param($url)

    Add-Type -AssemblyName System.Web
    [System.Web.HttpUtility]::UrlDecode($url)
}

function ConvertTo-EncodedUrl() {
    # Helper function: encode a url

    param($url)

    Add-Type -AssemblyName System.Web
    [System.Web.HttpUtility]::Urlcode($url)
}

function Convert-SafeLinkUrl() {
    # Helper function: decode a Microsoft Safe Link encoded url

    param([parameter(ValueFromPipeline)]$decodedUrl)

    $decodedUrl -match 'url=(\S+)&data=\S+' | Out-Null
    $decodedUrl -match 'url=(\S+)&amp;data=\S+' | Out-Null
    $matches[1]
}

#endregion

#region - DNS

function Resolve-DomainName() {
    param($name, $type = 'A', $server = '8.8.8.8')
    
    try { Resolve-DnsName -Name $name -Type $type -Server $server -DnsOnly }
    catch { Write-Warning $_ }
}

function Get-SpfRecord() {
    param($domain, $dnsServer = '8.8.8.8')

    try {
        Resolve-DnsName -Name $domain -Type TXT -Server $dnsServer -DnsOnly | 
        Where-Object { $_.Strings -like '*v=spf1*' }
    }
    catch { Write-Warning $_ }
}

function Convert-DNSNameToAscii() {
    # Helper function: converts an Internation Domain Name (IDN) to ASCII using punycode
    # details: https://en.wikipedia.org/wiki/IDN_homograph_attack

    param($string)

    $idnMapping = New-Object -TypeName 'System.Globalization.IdnMapping'
    $idnMapping.GetAscii($string)
}

function Convert-DNSNameToUnicode() {
    # Helper function: converts an punycode domain name back to IDN

    param($string)

    $idnMapping = New-Object -TypeName 'System.Globalization.IdnMapping'
    $idnMapping.GetUnicode($string)
}

function Find-SubDomain {
    param ($domain)

    $FormatEnumerationLimit = -1
    $baseUrl = 'https://www.threatcrowd.org/searchApi/v2/domain/report'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $(Invoke-WebRequest "$baseUrl/?domain=$domain" | ConvertFrom-Json) | 
    Select-Object -ExpandProperty subdomains
}

#endregion

#region - MDM

function Get-MDMTrackedEnrollment() {
    # Helper function: Find if package has been attempted to install via WMI-To-CSP bridge

    param( $CSPSearchString = 'VPNv2' )
    
    $regPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked'
    $trackedEnrollments = @()

    try {
        $regKey = $(Get-ChildItem -Recurse $($regPath) -ErrorAction Stop) | 
        Get-ItemProperty | Where-Object { $_ -ilike "*$CSPSearchString*" }

        $regKey | ForEach-Object {
            $trackedEnrollment = $_ | Select-Object -Property path*, pspath
            $guid = $($_.pspath).split('\')[-3]
            $trackedEnrollment | 
            Add-Member -MemberType NoteProperty -Name GUID -Value $guid
            $trackedEnrollments += $trackedEnrollment
        }
        
        $trackedEnrollment
    }
    catch { $error[0].Exception.Message }
}

function Remove-MDMEnrollment() {
    # Helper function: Remove specified registry keys to allow re-install via MDM (e.g. Intune or WMI-to-CSP Bridge)

    param(
        [Parameter(
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true
        )]$array
    )

    $regPathTrackedEnrollments = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked'
    $regPathEnrollments = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments'

    $array | ForEach-Object {
        try {
            $guid = $($_.guid)
            Remove-Item -Recurse "$regPathTrackedEnrollments\$guid" -ErrorAction Stop
            Remove-Item -Recurse "$regPathEnrollments\$guid" -ErrorAction Stop
        }
        catch { $error[0].Exception.Message }
    }
}

#endregion

#region - SMB

function Get-SmbPermissions() {
    # Helper function: audit a server's file share permissions (ntfs and smb)

    Get-SmbShare -IncludeHidden | 
    Where-Object { ($_.name -ne 'print$') -and ($_.path -notlike '*LocalsplOnly*') -and ($_.path -ne '') } | 
    Select-Object description, name, path | ForEach-Object {
        $smbPermissions = Get-SmbShareAccess -Name $_.Name | 
        Select-Object accountname, accessright, accesscontroltype

        $_ | Add-Member -MemberType NoteProperty -Name 'SMB Permissions' -Value $smbPermissions

        $ntfsPermission = $(Get-Acl -Path $($_.path)).Access | 
        Select-Object filesystemrights, accesscontroltype, identityreference
        $_ | Add-Member -MemberType NoteProperty -Name 'NTFS Permissions' -Value $ntfsPermission

        $_
    }
}

function Find-SmbPermissions() {
    # Helper function: find shares which an account has permissions on

    param(
        [parameter(ValueFromPipeline)]$shares,
        [Parameter(Position = 1, ValueFromRemainingArguments)]$account
    )

    # get shares that user has allow ntfs permissions on
    $shares | Where-Object {
        ( $_.'NTFS Permissions'.IdentityReference `
            -match [Regex]::Escape($account)
        ) -and ($_.'NTFS Permissions'.AccessControlType -match 'Allow')
    } | 
    # and shares where user has smb allow permissions on
    Where-Object { 
        ($_.'SMB Permissions'.accountname -match [Regex]::Escape($account)) `
            -and ($_.'SMB Permissions'.AccessControlType -match 'Allow')
    }
}

#endregion

#region - RSAT

function Get-WUServer() {
    # Helper function: Get Current WU Server Setting
    $regKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $(Get-ItemProperty -Path $regKey -Name 'UseWUServer').UseWUServer
}

function Set-WUServer() {
    # Helper function: Set WU Server to specified server

    param([parameter(valuefrompipeline)]$value)

    $regKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-ItemProperty -Path $regKey -Name 'UseWUServer' -Value $value
    Restart-Service wuauserv
}

function Install-WindowsCapability() {
    # Helper function: download / install windows features using Windows Update
    # inspired by: https://enterinit.com/windows-10-1809-and-later-install-rsat-feature/
    param($packages = 'RSAT*')

    Get-WindowsCapability -Name $packages -Online | ForEach-Object {
        $_ | Select-Object displayname, downloadsize, state
        $_ | Add-WindowsCapability -Online
    }
}

function Test-WindowsCapability() {
    # check if a windows feature has been installed

    param($package = 'RSAT*')

    Get-WindowsCapability -Name $package -Online | 
    Select-Object name, displayname, state
}

#endregion

#region - OS Info
function Invoke-WindowsActivation() {
    # Helper function: Attempts to activate windows
        
    $SoftwareLicensingService = Get-WmiObject -Class SoftwareLicensingService 
    $SoftwareLicensingService.RefreshLicenseStatus() | Out-Null
    'Sending Activation Request'
}

function Get-WindowsActivationStatus() {
    # Helper function: Gets windows activation status using a CIM query

    $wql = "SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE Name LIKE '%Windows%' AND PartialProductKey IS NOT NULL"
    $response = Get-CimInstance -Query $wql
    Switch ($response.licenseStatus) {
        0 { 'Unlicensed' }
        1 { 'Licensed' }
        2 { 'OOB Grace - Out-of-Box Grace Period' }
        3 { 'OOT Grace - Hardware Change Grace Period' }
        4 { 'Non-Genuine Grace - Failed Previous Activation' }
        5 { 'Notification - Unable to Activate' }
        6 { 'Extended Grace' }
    }
}

function Get-WindowsInstall() {
    # Helper function: Get basic information about the version of windows installed

    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | 
    Select-Object ProductName, DisplayVersion, CurrentBuild, 
    SystemRoot, InstallationType, EditionID,
    @{n = 'InstallDate'; e = {
            [System.TimeZone]::CurrentTimeZone.ToLocalTime(
                (Get-Date -Day 1 -Month 1 -Year 1970)
            ).AddSeconds($_.InstallDate)
        } 
    }
}
#endregion

function Get-OAuthToken() {
    # Helper Function: Gets OAuth Token for API authentication
    
    param( $clientId, $clientSecret, $resource, $uri, [switch]$verbose)

    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
    }

    if ($resource) { $body.Add('resource', $resource) }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $response = Invoke-RestMethod -Method Post -Uri $uri -Body $Body

    if ($verbose) { $response }
    else { $response.access_token }
}

function Start-EvalatedService() {
    # Helper Function: Start A Windows Service, Self-Elevate if needed
    # from http://www.expta.com/2017/03/how-to-self-elevate-powershell-script.html
    
    param($path)

    if ( $(Get-Service $name).Status -ne 'Running' ) {
        
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            if ([int](Get-CimInstance -Class Win32_OperatingSystem | 
                    Select-Object -ExpandProperty BuildNumber) -ge 6000) {
                Write-Warning "Attempting to start $name"
                try { 
                    Start-Process -FilePath PowerShell.exe -Verb Runas `
                        -ArgumentList "Start-Service -name '$name'" -WindowStyle Hidden 
                }
                catch { Write-Warning $_ }
            }
            else { Write-Warning "Auto-elevating not possible with this version of Windows, please start $name" }
        }
        else { Start-Service "$name" }
    }
}

function Get-ADUserPasswordExpiration() {
    # Helper function: Calculate days until password expiration
    
    # uses the AD property msDS-UserPasswordExpiryTimeComputed
    # requires ActiveDirectory module, available from the RSAT feature
    
    param( [Parameter(ValueFromPipeline)][object]$users )
    
    $($users | ForEach-Object {
            $user = Get-ADUser $_.SamAccountName -Properties msDS-UserPasswordExpiryTimeComputed
            $passwordExpiryTime = [datetime]::FromFileTime($user.'msDS-UserPasswordExpiryTimeComputed')

            $user | Add-Member -MemberType NoteProperty `
                -Name 'PasswordExpirationDate' `
                -Value $passwordExpiryTime -Force
            $user
        })
}

function Search-CensysHosts() {
    # Helper function: Uses the Censys API to find hosts on the internet
    # REQUIRED: free censys api key
    
    param($query, $apiId, $apiSecret)

    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($("$apiId" + ':' + "$apiSecret")))
    
    $headers = @{
        'Authorization' = "Basic $encodedCreds"
        'Content-Type'  = 'application/json'
    }

    $uri = 'https://search.censys.io/api/v2/hosts/search?q=$query'
    $response = Invoke-WebRequest -UseBasicParsing "$uri" -Headers $headers
    (($response.content | ConvertFrom-Json).result).hits
}