function Start-PacketCapture() {
    # wrapper around built-in Windows command 'netsh trace'
    # must be run as admin

    param(
        $path, 
        $ipProtocol = 6, # 6 for TCP, 17 for UDP
        $ipVersion = 'IPV4', 
        $interface = 'Ethernet'
    )

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Warning 'Script must be Run as Administrator.'
    }
    else {
        if (Test-Path $path) { Remove-Item $path }

        # capture ipv4, tcp traffic, no report cab file
        netsh trace start capture=yes CaptureInterface=$interface Ethernet.type=$ipVersion report=disabled Protocol=$ipProtocol tracefile=$path | Out-Null
    }
}