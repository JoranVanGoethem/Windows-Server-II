#------------------------------------------------------------------------------ 
# run
#------------------------------------------------------------------------------ 
firewall
IPconfiguratie
ActiveDirectory


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
$address = "192.168.25.10"
$prefix =  "24"

New-NetIPAddress `
    -InterfaceAlias $interface `
    -IPAddress $address `
    -PrefixLength $prefix

# dns caching uitschakelen op nat adapter
Get-NetAdapter "Ethernet 1" | Set-DNSClient -RegisterThisConnectionsAddress $False
}
#------------------------------------------------------------------------------ 
# Active Directory
#------------------------------------------------------------------------------
function ActiveDirectory{

# Variabelen
$voornaam = "Joran"
$domeinNaam = "WS2-25-$voornaam.hogent"
$domein = hogent
$LegacyName = "WS225JORAN"
$FFLevel = "Windows Server 2025"
$DFLevel = "Windows Server 2025"
$safemode = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force

# install
if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
}

# Forest configureren
if (-not (Get-ADDomain -ErrorAction SilentlyContinue)) {
    Install-ADDSForest `
        -DomainName $domeinNaam `
        -SafeModeAdministratorPassword $safemode `
        -DomainNetbiosName $LegacyName `
        -ForestMode $FFLevel `
        -DomainMode $DFLevel `
        -InstallDNS:$true `
        -Force
}

# OU configureren
Write-Host "=== Running post-reboot setup ==="
    # Create OUs, users, DNS zones, records, etc.
    $OUs = @("Admins", "Users", "IT")
    foreach ($ou in $OUs) {
        New-ADOrganizationalUnit -Name $ou -Path "DC=$domeinNaam,DC=$domein" -ProtectedFromAccidentalDeletion $false
    }

    # Example user creation
    $pw = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
    New-ADUser -Name $voornaam"Admin1" -SamAccountName $voornaam"Admin1" -AccountPassword $pw -Enabled $true -Path "OU=Admins,DC=$domeinNaam,DC=$domein"

# --- Domain Admins ---
Write-Host "=== admin gebruikers aanmaken ==="
$adminUsers = @(
    @{ Name = "Admin1"; SamAccountName = "Admin1"; OU = "Admins" },
    @{ Name = "Admin2"; SamAccountName = "Admin2"; OU = "Admins" }
)

foreach ($user in $adminUsers) {
    $exists = Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        Write-Host "Creating Domain Admin: $($user.Name)"
        $pw = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
        New-ADUser -Name $user.Name `
                   -SamAccountName $user.SamAccountName `
                   -AccountPassword $pw `
                   -Enabled $true `
                   -Path "OU=$($user.OU),DC=WS2-25-joran,DC=hogent"
        Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
    } else {
        Write-Host "User $($user.Name) already exists, skipping..."
    }
}

# --- Domain Users ---
Write-Host "=== admin gebruikers aanmaken ==="
$normalUsers = @(
    @{ Name = "User1"; SamAccountName = "User1"; OU = "Users" },
    @{ Name = "User2"; SamAccountName = "User2"; OU = "Users" }
)

foreach ($user in $normalUsers) {
    $exists = Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue
    if (-not $exists) {
        Write-Host "Creating Domain User: $($user.Name)"
        $pw = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
        New-ADUser -Name $user.Name `
                   -SamAccountName $user.SamAccountName `
                   -AccountPassword $pw `
                   -Enabled $true `
                   -Path "OU=$($user.OU),DC=WS2-25-joran,DC=hogent"
    } else {
        Write-Host "User $($user.Name) already exists, skipping..."
    }
}
}
#------------------------------------------------------------------------------ 
# Primaire DNS
#------------------------------------------------------------------------------ 
function DNS {
$zone = "example.com"
$network = "192.168.25.0/24"

# Controle installatie:
Get-WindowsFeature -Name *DNS*

# DNS installeren via PowerShell:
Add-WindowsFeature -Name DNS -IncludeManagementTools

# forward lookup
Add-DnsServerPrimaryZone -Name $zone -ZoneFile "$zone.com.DNS"

# reverse lookup
Add-DnsServerPrimaryZone -NetworkID $network -ReplicationScope"Forest"

# PTR-Record
Add-DnsServerResourceRecordPtr -Name "17" -ZoneName "25.168.192.in-addr.arpa" -PtrDomainName "host17.contoso.com"

}

#------------------------------------------------------------------------------ 
# DHCP
#------------------------------------------------------------------------------ 
function DHCP {
# Variabelen
$DNSName = "server1.$domeinNaam"
$scope = "ScopeHOGENT"
$startRange = "192.168.25.50"
$endRange = "192.168.25.150"
$subnet = "255.255.255.0"
$state = "Active"

# Installeren DHCP rol en bijhorende management tools
Install-WindowsFeatureDHCP–IncludeManagementTools

# DHCP service (her)starten
Restart-Service dhcpserver

# DHCP server autoriseren binnen AD
Add-DhcpServerInDC -DnsName $DNSName -IPAddress 192.168.25.10

# -------
$exclusionStart = "192.168.25.101"
$exclusionEnd = "192.168.25.150"
$id = 192.168.25.0

add-DhcpServerv4Scope -Name $scope -StartRange $startRange -EndRange $endRange -SubnetMask $subnet -State $state

Add-DhcpServerv4ExclusionRange -ScopeID $id -StartRange $exclusionStart -EndRange $exclusionEnd

}
#------------------------------------------------------------------------------ 
# CA
#------------------------------------------------------------------------------ 
function CA {

}
