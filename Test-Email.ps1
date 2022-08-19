# Required Helper Functions: Connect-Telnet, Send-TelnetCommand, Disconnect-Telnet

function Test-Email() {
    # use smtp command RCPT TO check if an email address exists

    param(
        $email,
        $fromServer = $fromServer,
        $fromAddress = $fromAddress,
        $port = 25,
        [switch]$verbose,
        $waitTime = 1000 #in milliseconds
    )

    if ($verbose) {
        $echo = $true
        $portCheck = $true
    }

    #region - check if smtp port is open, on mailserver
    $mailServer = $(Resolve-DnsName -Name $($email -split '@')[1] -Type mx | 
        Sort-Object preference | Select-Object -First 1).NameExchange
    
    $portParam = @(
        ComputerName = $mailServer 
        Port = $port 
        InformationLevel = Quiet 
        WarningAction = SilentlyContinue
    )
    
    if ($portCheck) { $portOpen = $(Test-NetConnection @portParam) }
    else { $portOpen = 'bypass' }
    #endregion
    
    if ($portOpen -or ($portOpen = 'bypass')) {
        
        #region - connect to mailserver
        Connect-Telnet -remoteHost $mailServer -port $port
        $telnetParam = @(
            Command = "EHLO $fromServer" 
            Verbose = $true 
            echo = $echo
        )
        $smtpConn = $(Send-TelnetCommand @telnetParam)
        #endregion

        if ($null -eq $smtpConn) { return "$mailServer`: Connection Closed." }
        else {
            # set FROM address
            if ($verbose) { $smtpConn }
            $mailFromParam = @(
                Command = "MAIL FROM: <$fromAddress>"
                Verbose = $verbose 
                echo = $echo
            )
            Send-TelnetCommand @mailFromParam
            
            # set RCPT TO address
            $rcptParam = @(
                Command = "RCPT TO: <$email>"
                Verbose = $true
                echo = $echo
            )
            $rcptResponse = $(Send-TelnetCommand @rcptParam )
            
            # close connection
            $(Send-TelnetCommand -command 'QUIT' -verbose $verbose -echo $echo)
            Disconnect-Telnet
        } 
    }
    else { return "$mailServer`:$port Timeout" }
    
    # check if the email address exists on the specified server
    if ($rcptResponse -ilike '*250*2.1.5*OK*') { $true }
    elseif ($rcptResponse -ilike '*250*recipient*ok*') { $true }
    else { $false }
}