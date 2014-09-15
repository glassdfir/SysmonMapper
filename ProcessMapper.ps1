#Parse Windows Security Logs for 4688 events
#Map processes to parent processes

[CmdletBinding(PositionalBinding=$false)]             
Param(
   [Parameter(Mandatory=$True)]
   [datetime]$StartDate,
   [Parameter(Mandatory=$True)]
   [datetime]$StopDate
)


$global:outputlines = @()

$outfile = "processmap.html"

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

$events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4688}|Where-Object { ( $_.TimeCreated -gt $StartDate -and $_.TimeCreated -le $StopDate)}|Sort-Object TimeCreated 
ForEach($event in $events){
    $eventxmldata = [xml]$event.toxml()
    $EventData = $eventxmldata.Event.EventData.Data
    $SubjectUserSid = $EventData | where {$_.name -eq "SubjectUserSid"}
    $SubjectDomainName = $EventData | where {$_.name -eq "SubjectDomainName"}
    $SubjectLogonId = $EventData | where {$_.name -eq "SubjectLogonId"}
    $NewProcessId = $EventData | where {$_.name -eq "NewProcessId"}
    $NewProcessName = $EventData | where {$_.name -eq "NewProcessName"}
    $TokenElevationType = $EventData | where {$_.name -eq "TokenElevationType"}
    $ProcessId = $EventData | where {$_.name -eq "ProcessId"}
    $CommandLine = $EventData | where {$_.name -eq "CommandLine"}
    $PIDNUM =[Convert]::ToInt32($NewProcessId.InnerText.Substring(2), 16)
    $PPIDNUM =[Convert]::ToInt32($ProcessId.InnerText.Substring(2), 16)
    $OutLine = "[{v:'" + $PIDNUM + "', f:'" + $PIDNUM + "<div>" + $event.TimeCreated + "<br>" + $NewProcessName."#text" + "</div>'},'" + $PPIDNUM + "', '']"
    $OutLine = $Outline -replace '\\','\\'
    $global:outputlines += $Outline
}
ForEach($line in $global:outputlines){
    If($global:outputlines.IndexOf($line) -eq $global:outputlines.GetUpperBound(0)){ $comma = " " } Else { $comma = ","}
    $line + $comma | Add-Content $outfile 
    }
$footer = "]);
 var chart = new google.visualization.OrgChart(document.getElementById('chart_div'));
        chart.draw(data, {allowHtml:true,allowCollapse:true});
      }
    </script>
  </head>

  <body>
    <div id='chart_div'></div>
  </body>
</html>
"
$footer| Add-Content $outfile
