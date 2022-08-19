function Invoke-TShark() {
    #powershell wrapper around tshark, part of the Wireshark install
    #allows programtic capture of traffic, output parseable by powershell

    param(
        $log = "$PathToScript\frame.log", 
        $wiresharkLocation = 'C:\Program Files\Wireshark',
        $capFile, $duration, $count, $interface, 
        $displayFilter, $captureFilter, $fields
    )

    # work around issue that PSScriptRoot isn't available with "run selection"
    if ($psISE) { 
        $PathToScript = Split-Path -Path $psISE.CurrentFile.FullPath 
    }
    else {
        if ($profile -match 'VScode') { 
            $PathToScript = Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
        } 
        else { $PathToScript = $PSScriptRoot }
    }

    # -r: read file, -i: interface, -c: count, -a: autostop, -V: verbose, 
    # -Q: very quiet, -T: text format, -P: print summary, -e: field, 
    # -f: capture filter, -Y: display filter -w: outfile -F: file format
    $options = @('-r', "$capFile", '-T', 'json')

    if ($fields) { $options += $fields }
    if ($count) { $options += @('-c', $count) }
    if ($duration) { $options += @('-a', "duration:$duration") }
    if ($displayFilter) { $options += @('-Y', $displayFilter) }
    if ($captureFilter) { $options += @('-f', $captureFilter) }

    & "$wiresharkLocation\tshark.exe" $options
}
