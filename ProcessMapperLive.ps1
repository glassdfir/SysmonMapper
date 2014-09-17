[CmdletBinding(PositionalBinding=$false)]             
Param(
   [Parameter(Mandatory=$False)]
   [String] $Remote =""
)


$global:outputlines = @()
$outfile = "liveprocessmap.html"
$ComputerName="LocalHost"




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
If($Remote=""){$ComputerName = $Remote}
$RunningProcesses = Get-WmiObject win32_process -ComputerName $ComputerName| select ProcessID,ParentProcessID,name,commandline 
ForEach($RunningProcess in $RunningProcesses){
    $processID = $RunningProcess.ProcessID
    $parentprocessID = $RunningProcess.ParentProcessID
    $processname = $RunningProcess.Name
    $commandline = $RunningProcess.CommandLine -replace "`'",""
    $commandline = $commandline -replace '"',""
    $OutLine = "[{v:'" + $processID + "', f:'" + $processID + "<div>" + $processname  + "</div>'},'" + $ParentProcessID + "','" + $commandline +"']"
          $OutLine = $Outline -replace '\\','\\'
                $global:outputlines+=$Outline

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
    <div id=`'chart_div`'></div>
  </body>
</html>
"
$footer| Add-Content $outfile