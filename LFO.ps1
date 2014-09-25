Param(
   [Parameter(Mandatory=$False)]
   [String] $Remote =""
)
$ComputerName="LocalHost"
If($Remote -ne ""){$ComputerName = $Remote}
$global:imagenames = @()
$Events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -ComputerName $ComputerName|Where-Object { ( $_.id -eq 1)}
ForEach($event in $Events){
    $eventxmldata = [xml]$event.toxml()
    $EventData = $eventxmldata.Event.EventData.Data
    $Image =$EventData | where {$_.name -eq "Image"}
    $global:imagenames += $Image."#text"
    }
$global:imagenames|group|sort-object -property count,Name|Format-Table -Property count,name -AutoSize| Ft -autosize | out-string -width 4096 
