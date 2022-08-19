function Get-WindowsProductKey {
    # Retrieve the Windows Product Key
    # Base24 Decrypt Algorithm from: http://mspowershell.blogspot.com/2010/11/sql-server-product-key.html

    param(
        [parameter(ValueFromPipeline)]
        $regKey = $(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
    )

    $keyArray = $regKey.DigitalProductId4[52..66]
    $chars = 'BCDFGHJKMPQRTVWXY2346789'
    $productKey = ''

    # decrypt base24 encoded binary data
    for ($i = 24; $i -ge 0; $i--) {
        $k = 0
        for ($j = 14; $j -ge 0; $j--) {
            $k = $k * 256 -bxor $keyArray[$j]
            $keyArray[$j] = [math]::truncate($k / 24)
            $k = $k % 24
        }

        $productKey = $chars[$k] + $productKey
        if ( ($i % 5 -eq 0) -and ($i -ne 0) ) {
            $productKey = '-' + $productKey
        }
    }

    $productKey
}