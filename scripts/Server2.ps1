#------------------------------------------------------------------------------ 
# run
#------------------------------------------------------------------------------ 
firewall
IPconfiguratie

#------------------------------------------------------------------------------ 
# Firewall
#------------------------------------------------------------------------------ 
function firewall {
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

}
#------------------------------------------------------------------------------ 
#  IP-configuratie
#------------------------------------------------------------------------------ 
function IPconfiguratie {

$interface = "Ethernet 2"
$address = "192.168.25.20"
$prefix =  "24"

New-NetIPAddress `
    -InterfaceAlias $interface `
    -IPAddress $address `
    -PrefixLength $prefix

# dns caching uitschakelen op nat adapter
Get-NetAdapter "Ethernet 1" | Set-DNSClient -RegisterThisConnectionsAddress $False
}

#------------------------------------------------------------------------------ 
# Secundaire DNS
#------------------------------------------------------------------------------ 

#------------------------------------------------------------------------------ 
# MS SQL
#------------------------------------------------------------------------------ 