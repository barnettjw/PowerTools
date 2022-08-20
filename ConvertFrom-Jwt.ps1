function ConvertFrom-Jwt {
    # parse a jwt token, commonly used with oauth and saml
    # adapted from: https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Alias('ih')][switch]$IncludeHeader,
        [switch]$msGraph
    )

    # Validate as per https://tools.ietf.org/html/rfc7519
    # Access and ID tokens are fine, Refresh tokens will not work
    if (!$Token.Contains('.') -or !$Token.StartsWith('eyJ')) { Write-Error 'Invalid token' -ErrorAction Stop }

    # Extract header and payload
    $tokenheader, $tokenPayload = $Token.Split('.').Replace('-', '+').Replace('_', '/')[0..1]

    #region - Fix padding 
    # fix padding as needed, keep adding "="" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { 
        Write-Debug 'Invalid length for a Base-64 char array or string, adding ='
        $tokenheader += '=' 
    }

    while ($tokenPayload.Length % 4) { 
        Write-Debug 'Invalid length for a Base-64 char array or string, adding ='
        $tokenPayload += '=' 
    }

    Write-Debug “Base64 encoded (padded) header:`n$tokenheader”
    Write-Debug “Base64 encoded (padded) payoad:`n$tokenPayload”
    #endregion

    # Convert header from Base64 encoded string to PSObject all at once
    $header = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json
    Write-Debug “Decoded header:`n$header”

    # Convert payload to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))
    Write-Debug “Decoded array in JSON format:`n$tokenArray”

    # Convert from JSON to PSObject
    $tokenObject = $tokenArray | ConvertFrom-Json

    if ($IncludeHeader) { $header }

    if ($msGraph) {
        # field references
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims
        # https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields
        [pscustomobject]@{
            Issuer              = $tokenObject.iss
            Subject             = $tokenObject.sub
            Audience            = $tokenObject.aud
            'Expiration Time'   = $(Get-Date $((Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($tokenObject.exp))).ToLocalTime() -Format g)
            'Not Before'        = $(Get-Date $((Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($tokenObject.nbf))).ToLocalTime() -Format g)
            'Issued at'         = $(Get-Date $((Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($tokenObject.iat))).ToLocalTime() -Format g)
            AppId               = $tokenObject.appid
            'Identity Provider' = $tokenObject.idp
            Roles               = $tokenObject.roles
            'Tenant id'         = $tokenObject.tid
            'Object id'         = $tokenObject.oid
            Version             = $tokenObject.ver
        }
    }
    else { $tokenObject }
}