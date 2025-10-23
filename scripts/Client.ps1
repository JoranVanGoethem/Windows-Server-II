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

# dns caching uitschakelen op nat adapter
Get-NetAdapter "Ethernet 1" | Set-DNSClient -RegisterThisConnectionsAddress $False

}

#------------------------------------------------------------------------------ 
# RSAT tools
#------------------------------------------------------------------------------ 

Get-WindowsFeature -Name RSAT*

# AD tools 
Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature

# DNS server tools
Install-WindowsFeature -Name DNS Server Tools -IncludeAllSubFeature

# DHCP tools
Install-WindowsFeature -Name DHCP Server Tools -IncludeAllSubFeature


#------------------------------------------------------------------------------ 
# SSMS
#------------------------------------------------------------------------------ 

https://aka.ms/ssms/21/release/vs_SSMS.exe

./vs_SSMS.exe