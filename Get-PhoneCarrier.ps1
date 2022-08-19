function Get-PhoneCarrier() {
    # calls the twillo phone carrier api
    # Requires: free twillo api key

    param($phone, $account_sid, $auth_token)

    $apiCall = "https://lookups.twilio.com/v1/PhoneNumbers/+1$($phone)?Type=carrier"
    
    # setup auth
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        ('{0}:{1}' -f $account_sid, $auth_token)
        )
    )
    $headers = @{ Authorization = ('Basic {0}' -f $base64AuthInfo) }
 
    # make api call
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $json = $((Invoke-WebRequest -Headers $headers -Uri $apiCall).content | 
        ConvertFrom-Json)
    $json.carrier | Add-Member -MemberType NoteProperty -Name phone -Value $phone

    # output results
    $json.carrier | Select-Object phone, name, type, error_code
}