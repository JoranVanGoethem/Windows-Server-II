

#------------------------------------------------------------------------------ 
# Firewall
#------------------------------------------------------------------------------ 
function firewall {
    Write-Host "======= Firewall services uitschakelen ======="

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

}
#------------------------------------------------------------------------------ 
#  IP-configuratie
#------------------------------------------------------------------------------ 
function IPconfiguratie {
    Write-Host "======= Ip adress aanpassen ======="

    $interface = "Ethernet 2"
    $address = "192.168.25.20"
    $prefix =  "24"

    $existingIP = Get-NetIPAddress -InterfaceAlias $interface -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $address }

    if (-not $existingIP) {
        New-NetIPAddress `
            -InterfaceAlias $interface `
            -IPAddress $address `
            -PrefixLength $prefix
    }else {
        Write-Host "Ip adress is al: $address"
    }

    # Stel de host-only interface in om server1 als DNS te gebruiken
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses 192.168.25.10

    # Controleer het opnieuw
    Get-DnsClientServerAddress -InterfaceAlias "Ethernet 2"


    # dns caching uitschakelen op nat adapter
    Get-NetAdapter "Ethernet" | Set-DNSClient -RegisterThisConnectionsAddress $False

}
#------------------------------------------------------------------------------ 
# Secundaire DNS
#------------------------------------------------------------------------------ 
function DNS_Secondary {

    $LDAPPath = "WS2-25-Joran"
    $domein = "hogent"
    $domeinNaam = "$LDAPPath.$domein"

    $zone = $domeinNaam  
    $primaryDNS = "192.168.25.10" # IP van de primaire DNS-server

    Write-Host "======= Secundaire DNS Configuratie ======="

    # DNS installeren
    Install-WindowsFeature DNS -IncludeManagementTools

    # Controleren of de zone al bestaat
    $secZone = Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue
    if (-not $secZone) {
        # Secondary zone aanmaken
        Add-DnsServerSecondaryZone -Name $zone -MasterServers $primaryDNS -ZoneFile "$zone.DNS"
        Write-Host "Secondary zone: $zone gecreerd, data wordt gehaald van de primaire DNS: $primaryDNS."
    } else {
        Write-Host "Secondary zone: $zone bestaat al, skippen..."
    }
}

#------------------------------------------------------------------------------ 
# MS SQL
#------------------------------------------------------------------------------ 
function MSSQL {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb" -Name ProtectionPolicy -Value 1 -PropertyType DWord -Force
    # Paden en instellingen
    $isoSource = "C:\vagrant\files\enu_sql_server_2022_standard_edition_x64_dvd_43079f69.iso"
    $isoPath   = "C:\tmp\files\enu_sql_server_2022_standard_edition_x64_dvd_43079f69.iso"

    Write-Host "======= Installatie SQL Server 2022 ======="

    # Zorg dat de doelmap bestaat
    New-Item -ItemType Directory -Path (Split-Path $isoPath) -Force | Out-Null

    # Kopieer ISO naar lokale map
    if (-not (Test-Path $isoPath)) {
        Write-Host "Kopieer ISO van gedeelde map naar lokale schijf..."
        Copy-Item -Path $isoSource -Destination $isoPath -Force
    }

    Write-Host "ISO wordt gebruikt: $isoPath"

    # Controleer dat de ISO bestaat
    if (-not (Test-Path $isoPath)) {
        Write-Error "ISO-bestand niet gevonden op $isoPath"
        return
    }

    # ISO mounten
    Write-Host "Mounten van ISO..."
    $mountResult = Mount-DiskImage -ImagePath $isoPath -PassThru
    $driveLetter = ($mountResult | Get-Volume).DriveLetter
    if (-not $driveLetter) {
        Write-Error "Kan ISO niet mounten."
        return
    }
    $sourcePath = "$($driveLetter):\"


    $SQLSysAdminAccount = "WS225JORAN\Admin1"

    # Start stille installatie
    Start-Process -FilePath $sourcePath\setup.exe -ArgumentList @(
        "/Q",
        "/ACTION=Install",
        "/FEATURES=SQLENGINE,REPLICATION,FULLTEXT,TOOLS",
        "/INSTANCENAME=MSSQLSERVER",
        # FIX: SQL Install werkt niet zonder deze parameters
        "/SQLSVCACCOUNT=""NT AUTHORITY\SYSTEM""",
        "/AGTSVCACCOUNT=""NT AUTHORITY\SYSTEM""",
        "/SQLSYSADMINACCOUNTS=$SQLSysAdminAccount",
        "/IACCEPTSQLSERVERLICENSETERMS",
        "/TCPENABLED=1",
        "/UPDATEENABLED=FALSE",
        "/SAPWD=25Admin26!",
        "/SECURITYMODE=SQL"
    ) -Wait

    Write-Host "SQL Server 2022 installatie voltooid."
}
#------------------------------------------------------------------------------ 
# Domeinlid maken
#------------------------------------------------------------------------------
function Join-Domain {
    param (
        [string]$DomainName = "WS2-25-Joran.hogent",
        [string]$DomainAdmin  = "Admin1"
        
    )
    $DomainAdminPassword = "P@ssword123"

    # Controleer of machine al lid is van het domein
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    if ($currentDomain -eq $DomainName) {
        Write-Host "Machine is al lid van domein: $DomainName, skippen..."
        return
    }

    Write-Host "Machine wordt lid van domein: $DomainName..."

    $securePassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("$DomainName\$DomainAdmin", $securePassword)

    # Lid worden van domein
    Write-Host "Rebooting Server... ,gelieve script opnieuw te starten !!!" 
    Add-Computer -DomainName $DomainName -Credential $cred -Restart -Force
}
#------------------------------------------------------------------------------ 
# Helper: Run as Domain Admin
#------------------------------------------------------------------------------ 
function RunAsDomainAdminInline {
    param (
        [string]$FunctionName
    )

    $domainAdmin = "WS225JORAN\Admin1"
    $password = ConvertTo-SecureString "P@ssword123" -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($domainAdmin, $password)

    Write-Host "==> Uitvoeren van $FunctionName als $domainAdmin ..."

    # Definieer de functie eerst in de remote sessie, dan roep je ze aan
    $functionDef = (Get-Command $FunctionName).Definition

    Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {
        param($fnName, $fnBody)
        # functie opnieuw definiëren in remote sessie
        Invoke-Expression "function $fnName { $fnBody }"
        & $fnName
    } -ArgumentList $FunctionName, $functionDef
}



#------------------------------------------------------------------------------ 
# run
#------------------------------------------------------------------------------ 
firewall
IPconfiguratie
Join-Domain
RunAsDomainAdminInline -FunctionName "DNS_Secondary"
RunAsDomainAdminInline -FunctionName "MSSQL"
Write-Host "======= Server 2 Volledig Geconfigureerd ======="