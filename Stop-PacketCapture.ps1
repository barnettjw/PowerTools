function Stop-PacketCapture() {
    # stop running netsh trace session

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Warning 'Script must be Run as Administrator.'
    }
    else { netsh trace stop }
}