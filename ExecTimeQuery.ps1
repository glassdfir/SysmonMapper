Param(
   [Parameter(Mandatory=$False)]
   [String] $Remote ="",
   [Parameter(Mandatory=$True)]
   [String] $query ="",
   [Parameter(Mandatory=$False)]
   [Switch] $exact = $False
)
$ComputerName="LocalHost"
If($Remote -ne ""){$ComputerName = $Remote}
If($exact){
    $events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath 'Event[System[EventID=1] and EventData[Data[@Name="Image"]="4"]]'
    ForEach($event in $events){$event.TimeCreated}
    }
    Else{

        $events = get-winevent -LogName microsoft-windows-sysmon/operational -ComputerName $ComputerName|Where-Object { ( $_.id -eq 1)}
        ForEach($event in $events){
            $image = $event |% {(([xml]$_.toxml()).Event.EventData.Data | ? {$_.name -eq "Image" })."#text"}
            if($image -match $query){Write-host ($event.TimeCreated.ToString() + "`t" + $image)}
        }
}