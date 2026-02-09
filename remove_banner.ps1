$taskname = "RemoveBanner"
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '-NoProfile -WindowStyle Hidden -Command set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name legalnoticecaption -value ""' 
$Trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger
$taskname = "RemoveBanner2"
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '-NoProfile -WindowStyle Hidden -Command set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name  legalnoticetext -value ""' 
$Trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger
