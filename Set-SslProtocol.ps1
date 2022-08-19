function Set-SslProtocol() {
    # enable or disable ssl/tls versions

    param(
        [validateset('Client', 'Server')]$type, 
        [validateset('enable', 'disable')]$action,
        [validateset('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 
            'TLS 1.1', 'TLS 1.2', 'TLS 1.3')]$protocol
    )

    $SChannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' 
    
    $param = @(
        Path = "$SChannel\$protocol\$type"
        PropertyType = 'DWord'
        ErrorAction = Stop
    )

    try {
        if ($action -eq 'enable') {
            New-Item "$SChannel\$protocol\$type" -Force -ErrorAction Stop
            New-ItemProperty @param -Name 'Enabled' -Value '1' -Force
            New-ItemProperty @param -Name 'DisabledByDefault' -Value 0 -Force
        }

        if ($action -eq 'disable') {
            New-Item "$SChannel\$protocol\$type" -Force -ErrorAction Stop
            New-ItemProperty @param -Name 'Enabled' -Value '0' -Force
            New-ItemProperty @param -Name 'DisabledByDefault' -Value 1 -Force
        }
    }
    catch { Write-Warning $_ }
}