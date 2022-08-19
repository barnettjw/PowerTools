function Test-Port() {
    # Test network ports with configurable timeout
    
    # adapted from: https://superuser.com/questions/805621/test-network-ports-faster-with-powershell/1214699#1214699
    param($computer, $port, $timeout = 3000, [switch]$quiet)

    # setup TCP socket
    $state = $null
    $requestCallback = $state
    $client = New-Object System.Net.Sockets.TcpClient

    # connect to port using TCP socket
    $client.BeginConnect($computer, $port, $requestCallback, $state) | Out-Null
    Start-Sleep -Milliseconds $timeOut

    # get results
    if ($client.Connected) {$open = $true } 
    else { $open = $false }
    $client.Close()

    # output
    if($quiet) { $open }
    else { 
        [pscustomobject]@{
            computer = $computer
            port = $port
            open = $open
        }
    }
}