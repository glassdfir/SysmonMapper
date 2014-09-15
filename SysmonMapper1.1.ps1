
# Type 1
# 0 - UtcTime
# 1 - ProcessGuid
# 2 - ProcessId
# 3 - Image
# 4 - CommandLine
# 5 - User
# 6 - LogonId
# 7 - TerminalSessionId
# 8 - IntegrityLevel
# 9 - HashType
# 10 - Hash
# 11 - ParentProcessGuid
# 12 - ParentProcessId
# 13 - ParentImage
# 14 - ParentCommandLine

#Type2
# 0 - UtcTime
# 1 - ProcessGuid
# 2 - ProcessId
# 3 - Image
# 4 - TargetFilename
# 5 - CreationUtcTime
# 6 - PreviousCreationUtcTime

#Type3
# 0 - UtcTime
# 1 - ProcessGuid
# 2 - ProcessId
# 3 - Image
# 4 - User
# 5 - Protocol
# 6 - SourceIsIpv6
# 7 - SourceIp
# 8 - SourceHostname
# 9 - SourcePort
# 10 - SourcePortName
# 11 - DestinationIsIpv6
# 12 - DestinationIp
# 13 - DestinationHostname
# 14 - DestinationPort
# 15 - DestinationPortName



[CmdletBinding(PositionalBinding=$false)]             
Param(
   [Parameter(Mandatory=$False)]
   [Switch] $FA = $false, #File Access
   [Parameter(Mandatory=$False)]
   [Switch] $NA = $false, #Network Access
   [Parameter(Mandatory=$False)]
   [Int] $P = 0,
   [Parameter(Mandatory=$True)]
   [datetime]$StartDate,
   [Parameter(Mandatory=$True)]
   [datetime]$StopDate
)
$global:outputlines = @()

$outfile = "sysmonmap.html"

$Header = "
<html>
<head>
<script type='text/javascript' src='https://www.google.com/jsapi'></script>
<script type='text/javascript'>
google.load('visualization', '1', {packages:['orgchart']});
google.setOnLoadCallback(drawChart);
function drawChart() {
var data = new google.visualization.DataTable();
data.addColumn('string', 'ProcessID');
data.addColumn('string', 'Label');
data.addColumn('string', 'ToolTip');
data.addRows([
" 
$Header| Out-File $outfile

If($P -ne ""){
    $events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational 
    $ParentProcessEvents = $events|Where-Object { ($_.TimeCreated -le $StopDate -and $_.id -eq 1)}|Sort-Object TimeCreated -Descending
    Function GetParentProcessPath{
    Param($PidPie)
        ForEach($event in $ParentProcessEvents){
            $eventxmldata = [xml]$event.toxml()
            $EventData = $eventxmldata.Event.EventData.Data
            $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
            $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
            $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
            $Image = $EventData | where {$_.name -eq "Image"}
            $CommandLine = $EventData | where {$_.name -eq "CommandLine"}
            $User = $EventData | where {$_.name -eq "User"}
            $LogonId = $EventData | where {$_.name -eq "LogonId"}
            $TerminalSessionId = $EventData | where {$_.name -eq "TerminalSessionId"}
            $IntegrityLevel = $EventData | where {$_.name -eq "IntegrityLevel"}
            $HashType = $EventData | where {$_.name -eq "HashType"}
            $Hash = $EventData | where {$_.name -eq "Hash"}
            $ParentProcessGuid = $EventData | where {$_.name -eq "ParentProcessGuid"}
            $ParentProcessId = $EventData | where {$_.name -eq "ParentProcessId"}
            $ParentImage = $EventData | where {$_.name -eq "ParentImage"}
            $ParentCommandLine = $EventData | where {$_.name -eq "ParentCommandLine"}
            If($ProcessId."#Text" -eq $PidPie.ToString()){
                $ToolTip = @()
                ForEach($eventdataprop in $EventData){
                    $PropValueClean = $eventdataprop."#text"
                    $PropValueClean = $PropValueClean -replace '"',""
                    $PropValueClean = $PropValueClean -replace "`'",""
                    $ToolTip+="`'" + $eventdataprop.name + " : " + $PropValueClean + "`'"
                }
                $ToolTipString = $ToolTip -join ","
                $OutLine = "[{v:'" + $ProcessId."#text" + "', f:'" + $ProcessId."#text" + "<div>" + $UtcTime."#text" + "<br>" + $Image."#text" + "</div>'},'" + $ParentProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                $OutLine = $Outline -replace '\\','\\'
                $global:outputlines+=$Outline
                Return $ParentProcessId."#Text"}
            }
     }
     $YaPPID = GetParentProcessPath($P)
     While($YaPPID -ne 4){
        $YaPPID = GetParentProcessPath($YaPPID)
        }
     $ChildProcessEvents = $events|Where-Object { ($_.TimeCreated -le $StopDate -and $_.TimeCreated -ge $StartDate)}|Sort-Object TimeCreated
     
     Function GetChildProcessEvents{
        Param($PidPie)
        ForEach($event in $ChildProcessEvents){
            $eventxmldata = [xml]$event.toxml()
            $EventData = $eventxmldata.Event.EventData.Data
            $ToolTip = @()
            ForEach($eventdataprop in $EventData){
                $PropValueClean = $eventdataprop."#text"
                $PropValueClean = $PropValueClean -replace '"',""
                $PropValueClean = $PropValueClean -replace "`'",""
                $ToolTip+="`'" + $eventdataprop.name + " : " + $PropValueClean + "`'"
            }
            $ToolTipString = $ToolTip -join ","
            switch($event.id){
                1 {
                    $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
                    $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
                    $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
                    $Image = $EventData | where {$_.name -eq "Image"}
                    $CommandLine = $EventData | where {$_.name -eq "CommandLine"}
                    $User = $EventData | where {$_.name -eq "User"}
                    $LogonId = $EventData | where {$_.name -eq "LogonId"}
                    $TerminalSessionId = $EventData | where {$_.name -eq "TerminalSessionId"}
                    $IntegrityLevel = $EventData | where {$_.name -eq "IntegrityLevel"}
                    $HashType = $EventData | where {$_.name -eq "HashType"}
                    $Hash = $EventData | where {$_.name -eq "Hash"}
                    $ParentProcessGuid = $EventData | where {$_.name -eq "ParentProcessGuid"}
                    $ParentProcessId = $EventData | where {$_.name -eq "ParentProcessId"}
                    $ParentImage = $EventData | where {$_.name -eq "ParentImage"}
                    $ParentCommandLine = $EventData | where {$_.name -eq "ParentCommandLine"}
                    If($ParentProcessId."#Text" -eq $PidPie.ToString()){
                    $OutLine = "[{v:'" + $ProcessId."#text" + "', f:'" + $ProcessId."#text" + "<div>" + $UtcTime."#text" + "<br>" + $Image."#text" + "</div>'},'" + $ParentProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                    $OutLine = $Outline -replace '\\','\\'
                    $global:outputlines+=$Outline
                    }
                }
                2 {
                    If($FA){
                        $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
                        $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
                        $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
                        $Image = $EventData | where {$_.name -eq "Image"}
                        $TargetFileName = $EventData | where {$_.name -eq "TargetFileName"}
                        $CreationUtcTime = $EventData | where {$_.name -eq "CreationUtcTime"}
                        $PreviousCreationUtcTime = $EventData | where {$_.name -eq "PreviousCreationUtcTime"}
                        If($ProcessId."#text"=$PidPie.ToString()){
                            $OutLine = "[{v:'" + $TargetFileName."#text" + "', f:'" + $CreationUtcTime."#text" + "<div style="+ [char]34  + "background-color: blue; color:white"+ [char]34 + ">" + $TargetFileName."#text" + "</div>'},'" + $ProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                            $OutLine = $Outline -replace '\\','\\'
                            $global:outputlines+=$Outline
                        }
                    }              
                }     
                3 {
                    If($NA){
                        $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
                        $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
                        $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
                        $Image = $EventData | where {$_.name -eq "Image"}
                        $User = $EventData | where {$_.name -eq "User"}
                        $Protocol = $EventData | where {$_.name -eq "Protocol"}
                        $SourceIsIpv6 = $EventData | where {$_.name -eq "SourceIsIpv6"}
                        $SourceIp = $EventData | where {$_.name -eq "SourceIP"}
                        $SourceHostname = $EventData | where {$_.name -eq "SourceHostname"}
                        $SourcePort = $EventData | where {$_.name -eq "SourcePort"}
                        $SourcePortName = $EventData | where {$_.name -eq "SourcePortName"}
                        $DestinationIsIpv6 = $EventData | where {$_.name -eq "DestinationIsIpv6"}
                        $DestinationIp = $EventData | where {$_.name -eq "DestinationIP"}
                        $DestinationHostname = $EventData | where {$_.name -eq "DestinationHostname"}
                        $DestinationPort = $EventData | where {$_.name -eq "DestinationPort"}
                        $DestinationPortName = $EventData | where {$_.name -eq "DestinationPortName"}
                        $rand = Get-Random
                        If($ProcessId."#text"=$PidPie.ToString()){
                            $OutLine = "[{v:'" + $rand + $rand + "', f:'<div style="+ [char]34  + "background-color: green; color:white"+ [char]34 + "><div>" + $DestinationHostname."#text" + "</div><div>DST: " + $DestinationIp."#text" + ":" + $DestinationPort."#text" + "</div></div>'},'" + $ProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                            $OutLine = $Outline -replace '\\','\\'
                            $global:outputlines+=$Outline
                        }
                    }
                }
                
			}
		}
	}        
    GetChildProcessEvents($P)
} 
else {

    $events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational |Where-Object { ( $_.TimeCreated -gt $StartDate -and $_.TimeCreated -le $StopDate)}|Sort-Object TimeCreated
    ForEach($event in $events){
        $eventxmldata = [xml]$event.toxml()
        $EventData = $eventxmldata.Event.EventData.Data
        $ToolTip = @()
        ForEach($eventdataprop in $EventData){
            $PropValueClean = $eventdataprop."#text"
            $PropValueClean = $PropValueClean -replace '"',""
            $PropValueClean = $PropValueClean -replace "`'",""
            $ToolTip+="`'" + $eventdataprop.name + " : " + $PropValueClean + "`'"
            }
        $ToolTipString = $ToolTip -join ","
        switch($event.id)
            {
                1 {
                    $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
                    $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
                    $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
                    $Image = $EventData | where {$_.name -eq "Image"}
                    $CommandLine = $EventData | where {$_.name -eq "CommandLine"}
                    $User = $EventData | where {$_.name -eq "User"}
                    $LogonId = $EventData | where {$_.name -eq "LogonId"}
                    $TerminalSessionId = $EventData | where {$_.name -eq "TerminalSessionId"}
                    $IntegrityLevel = $EventData | where {$_.name -eq "IntegrityLevel"}
                    $HashType = $EventData | where {$_.name -eq "HashType"}
                    $Hash = $EventData | where {$_.name -eq "Hash"}
                    $ParentProcessGuid = $EventData | where {$_.name -eq "ParentProcessGuid"}
                    $ParentProcessId = $EventData | where {$_.name -eq "ParentProcessId"}
                    $ParentImage = $EventData | where {$_.name -eq "ParentImage"}
                    $ParentCommandLine = $EventData | where {$_.name -eq "ParentCommandLine"}
                    $OutLine = "[{v:'" + $ProcessId."#text" + "', f:'" + $ProcessId."#text" + "<div>" + $UtcTime."#text" + "<br>" + $Image."#text" + "</div>'},'" + $ParentProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                    $OutLine = $Outline -replace '\\','\\'
                    $global:outputlines+=$Outline
                    }

                   2 {
                        If($FA){
                        $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
                        $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
                        $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
                        $Image = $EventData | where {$_.name -eq "Image"}
                        $TargetFileName = $EventData | where {$_.name -eq "TargetFileName"}
                        $CreationUtcTime = $EventData | where {$_.name -eq "CreationUtcTime"}
                        $PreviousCreationUtcTime = $EventData | where {$_.name -eq "PreviousCreationUtcTime"}
                        $OutLine = "[{v:'" + $TargetFileName."#text" + "', f:'" + $CreationUtcTime."#text" + "<div style="+ [char]34  + "background-color: blue; color:white"+ [char]34 + ">" + $TargetFileName."#text" + "</div>'},'" + $ProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                        $OutLine = $Outline -replace '\\','\\'
                        $global:outputlines+=$Outline
                        }
                    }
                   3 {
                    If($NA){ 
                        $UtcTime = $EventData | where {$_.name -eq "UtcTime"}
                        $ProcessGuid = $EventData | where {$_.name -eq "ProcessGuid"}
                        $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
                        $Image = $EventData | where {$_.name -eq "Image"}
                        $User = $EventData | where {$_.name -eq "User"}
                        $Protocol = $EventData | where {$_.name -eq "Protocol"}
                        $SourceIsIpv6 = $EventData | where {$_.name -eq "SourceIsIpv6"}
                        $SourceIp = $EventData | where {$_.name -eq "SourceIP"}
                        $SourceHostname = $EventData | where {$_.name -eq "SourceHostname"}
                        $SourcePort = $EventData | where {$_.name -eq "SourcePort"}
                        $SourcePortName = $EventData | where {$_.name -eq "SourcePortName"}
                        $DestinationIsIpv6 = $EventData | where {$_.name -eq "DestinationIsIpv6"}
                        $DestinationIp = $EventData | where {$_.name -eq "DestinationIP"}
                        $DestinationHostname = $EventData | where {$_.name -eq "DestinationHostname"}
                        $DestinationPort = $EventData | where {$_.name -eq "DestinationPort"}
                        $DestinationPortName = $EventData | where {$_.name -eq "DestinationPortName"}
                        $rand = Get-Random
                        $OutLine = "[{v:'" + $rand + $rand + "', f:'<div style="+ [char]34  + "background-color: green; color:white"+ [char]34 + "><div>" + $DestinationHostname."#text" + "</div><div>DST: " + $DestinationIp."#text" + ":" + $DestinationPort."#text" + "</div></div>'},'" + $ProcessId."#text" + "', tooltip(" + $ToolTipString +")]"
                        $OutLine = $Outline -replace '\\','\\'
                        $global:outputlines+=$Outline
                        }
                    }
                }
            }
    }
ForEach($line in $global:outputlines){
    If($global:outputlines.IndexOf($line) -eq $global:outputlines.GetUpperBound(0)){ $comma = " " } Else { $comma = ","}
    $line + $comma | Add-Content $outfile 
    }
$footer = "]);
 var chart = new google.visualization.OrgChart(document.getElementById('chart_div'));
        chart.draw(data, {allowHtml:true,allowCollapse:true});
      }
    function tooltip() {
    var thing =`"`";
    for (var i = 0, j = arguments.length; i < j; i++){
        thing = thing + `"\n`" + arguments[i];
    }
    return thing;
    }

    </script>
  </head>

  <body>
    <div id=`'chart_div`'></div>
  </body>
</html>
"
$footer| Add-Content $outfile
