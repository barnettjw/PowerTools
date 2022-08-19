function Connect-AWSSessionManager() {
    # powershell wrapper around AWS Session Manager
    # requires ssm to be installed

    param($instanceId, $localPort = 55678, $port = 3389)

    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    Start-Job -Name ssm -ArgumentList $instanceId, $localPort, $port -ScriptBlock {
        param($instanceId, $localPort, $port)
        Invoke-Expression "aws ssm start-session --target $instanceId --document-name AWS-StartPortForwardingSession --parameters `"localPortNumber=$localPort,portNumber=$port`""
    } | Out-Null
    
    Start-Sleep 2
    $connection = Receive-Job ssm
    if ($connection | Select-String "Port $localport opened" -Quiet) {
        if ($port -eq 3389) { mstsc /v:localhost:$localPort }
        if ($port -eq 22) { putty.exe localhost:$localport }
    }
    else { $connection | Select-String 'Cannot perform start session' }
}