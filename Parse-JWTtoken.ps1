function ConvertFrom-JWTtoken {
    # converts a jwt token into an object, to debug SAML issues

    # adapted from: https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    # reference: https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields

    [cmdletbinding()]param([Parameter(Mandatory = $true)][string]$token)
 
    # Validate as per https://tools.ietf.org/html/rfc7519
    # Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains('.') -or !$token.StartsWith('eyJ')) { 
        Write-Error 'Invalid token' -ErrorAction Stop 
    }
 
    #region - token header
    $tokenheader = $token.Split('.')[0].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) {  
        Write-Verbose 'Invalid length for a Base-64 char array or string, adding ='
        $tokenheader += '='
    }
    Write-Verbose 'Base64 encoded (padded) header:'
    Write-Verbose $tokenheader
            
    $decodedHeader = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json
    Write-Verbose 'Decoded header:'
    Write-Verbose $decodedHeader
    #endregion
 
    #region - token payload
    $tokenPayload = $token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { 
        Write-Verbose 'Invalid length for a Base-64 char array or string, adding ='
        $tokenPayload += '=' 
    }
    Write-Verbose 'Base64 encoded (padded) payoad:'
    Write-Verbose $tokenPayload
    #endregion
    
    #region - Decode Base64-encoded JSON
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose 'Decoded array in JSON format:'
    Write-Verbose $tokenArray
    #endregion
    
    $tokenObject = $tokenArray | ConvertFrom-Json
    Write-Verbose 'Decoded Payload:'
    $tokenObject
}