function Set-SslCipher() {
    # enable / disable SSL Cipher Suites 

    param(
        [validateset('enable', 'disable')]$action,
        [validateset('NULL', 'DES 56/56', 
            'RC2 128/128', 'RC2 40/128', 'RC2 56/128', 
            'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 
            'Triple DES 168', 'AES 128/128', 'AES 256/256')]$suite
    )

    $SChannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' 
    
    $param = @(
        Path = "$SChannel\$suite"
        Name = 'Enabled'
        PropertyType = 'DWord'
        ErrorAction = Stop
    )

    try {
        if ($action -eq 'enable') {
            New-Item "$SChannel\$suite" -Force -ErrorAction Stop
            New-ItemProperty @param -Value '1' -Force
        }

        if ($action -eq 'disable') {
            New-Item "$SChannel\$suite" -Force -ErrorAction Stop
            New-ItemProperty @param -Value '0' -Force
        }
    }
    catch { Write-Warning $_ }
}