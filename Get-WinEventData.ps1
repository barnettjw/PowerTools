function Get-WinEventData() {
    # Parse Event Log XML data

    param($events)

    $eventDetails = @()
    $events | ForEach-Object {
        [xml]$xmlEvent = $_.ToXml()
        $myEvent = $xmlevent.Event.System
        $xmlEvent.event.eventdata.Data | ForEach-Object {
            $myEvent | Add-Member -MemberType NoteProperty -Name EventData_$($_.name) -Value $($_.'#text')
        }

        $myEvent | Add-Member -MemberType NoteProperty -Name 'Provider' -Value $($_.providername) -Force
        $myEvent | Add-Member -MemberType NoteProperty -Name 'TimeCreated' -Value $($_.timecreated) -Force
        $eventDetails += $myEvent

        $eventDetails
    }
}