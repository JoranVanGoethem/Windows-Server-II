**Joran Van Goethem 3B2**

# Deployment Plan – Windows Server II

Dit document beschrijft hoe je de volledige testomgeving uitrolt. De handleiding is opgesteld zodat een eerstejaarsstudent Toegepaste Informatica de omgeving kan opzetten, enkel met de scripts en de commando’s hieronder.

---

## 1. Voorbereiding

### Optie A: Met GitHub

1. Navigeer naar: [GitHub repo](https://github.com/JoranVanGoethem/Windows-Server-II)
2. Clone de repository naar de gewenste locatie op je pc:

   ```powershell
   git clone https://github.com/JoranVanGoethem/Windows-Server-II.git
   ```
3. Download de SQL Server ISO:
   [SQL Server 2022 Standard Edition](https://downloads.academicsoftware.eu/sql/enu_sql_server_2022_standard_edition_x64_dvd_43079f69.iso)
4. Plaats de gedownloade ISO in de folder `scripts/files`.

### Optie B: Met ZIP-bestand

1. Maak de volgende mapstructuur aan:

   ```
   Windows-Server-II
   ├─ scripts
   │   └─ files
   └─ Vagrant
   ```
2. Pak de zipfile uit:

   * Plaats `Client.ps1`, `Server1.ps1` en `Server2.ps1` in de map **scripts**
   * Plaats `Vagrantfile` in de map **Vagrant**
3. Download de SQL Server ISO (zelfde link als hierboven) en plaats deze in de map `scripts/files`.

---

## 2. Algemeen

1. Open een PowerShell of Git Bash in de map `Vagrant`.
2. Start de virtuele machines **zonder provision** uit te voeren:

   ```powershell
   vagrant up --no-provision
   ```

> Opmerking: Provisioning gebeurt apart per server om herstartproblemen te vermijden.

---

## 3. Server 1 – Primaire server

1. Open PowerShell in de map `Vagrant`.
2. Voer het provisioning-commando uit:

   ```powershell
   vagrant provision server1
   ```
3. Tijdens het script verschijnt een waarschuwing:

   ```
   Rebooting Server... please start the script again
   ```

   **Wacht ±10 minuten** totdat de server volledig herstart is (controleer in VirtualBox GUI).
4. Voer het provisioning-commando opnieuw uit:

   ```powershell
   vagrant provision server1
   ```

> De server is nu volledig geconfigureerd (AD, DNS, DHCP, Firewall, etc.).
> Let op: de Certificate Authority is deels geïnstalleerd; volledige configuratie kan handmatig nodig zijn.

---

## 4. Server 2 – Secundaire server

1. Open PowerShell in de map `Vagrant`.
2. Voer het provisioning-commando uit:

   ```powershell
   vagrant provision server2
   ```
3. Tijdens het script verschijnt dezelfde waarschuwing:

   ```
   Rebooting Server... please start the script again
   ```

   **Wacht ±5 minuten** totdat de server volledig herstart is (controleer in VirtualBox GUI).
4. Voer het provisioning-commando opnieuw uit:

   ```powershell
   vagrant provision server2
   ```

> De server is nu volledig geconfigureerd (secundaire DNS, firewall, IP-configuratie).
> Let op: MSSQL-installatie werkt deels; service komt niet automatisch online. Handmatige controle is nodig.

---

## 5. Client

1. Open PowerShell in de map `Vagrant`.
2. Voer het provisioning-commando uit:

   ```powershell
   vagrant provision Client
   ```

> De client is nu volledig ingesteld, inclusief RSAT-tools en SSMS-installatie.

---

## 6. Overzicht gebruikers en wachtwoorden

| Gebruiker         | Groep    | Wachtwoord   |
| ----------------- | -------- | ------------ |
| **vagrant**       | lokaal   | `Vagrant`    |
| **Administrator** | Admin    | `P@ssword123` |
| **Admin1**        | Admin    | `P@ssword123` |
| **Admin2**        | Admin    | `P@ssword123` |
| **User1**         | employee | `P@ssword123` |
| **User2**         | IT       | `P@ssword123` |

> Tip: gebruik deze accounts voor inloggen, script-executie en testen van permissies.

---

## 7. Huidige status van de omgeving

### Server 1

* [x] Firewall
* [x] IP-configuratie
* [x] Active Directory
* [x] DNS
* [x] DHCP
* [ ] CA (gedeeltelijk werkend)

### Server 2

* [x] Firewall
* [x] IP-configuratie
* [x] Secundaire DNS
* [ ] MSSQL (gedeeltelijk werkend)

### Client

* [x] Firewall
* [x] IP-configuratie
* [x] RSAT
* [x] SSMS Client

---

## 8. Problemen & oplossingen

* **Rechten voor DHCP en CA:** 
bij het implementeren van één script was er een probleem met de rechten voor het uitvoeren van DHCP en CA. 
Hiervoor heb ik een nieuwe function gemaakt die een `Invoke-Command` uitvoert op de server met de benodigde credentials.

* **Provisioning Server1:**
dan heb ik een probleem bij het uitvoeren van mijn server1 script via vagrant. bij het laatste stuk van deel 1, namelijk Acitve directory, loopt vagrant op een aantal problemen, eerst had ik dat vagrant errors gaf over de verbinding niet meer kon maken en dat er nog een script aan het lopen was, daarbij sloot vagrant de vm af en verwijderde hij deze. Deze problemen heb ik deels kunnen oplossen maar niet volledig, Ik heb een exit 0 statement toegevoegd zodat het script gestopt wordt, dit verholp de delete, daarnaast provision ik in een apart commando en niet meer bij up dit zorgt ervoor dat hij de vm niet uitschakeld. het enige probleem nu is de wachttijd door de error en de error melding zichzelf. opzich is het geen groot probleem want na AD moet de server toch opnieuw opstarten en wordt het provisionen opnieuw gerunned.

* **SQL Server & CA service problemen**
sql server installeerd, maar de service komt maar niet online. hetzelfde voor CA wordt geconfigureerd als admin maar komt niet tevoorschijn.

---

<!-- 3. Een korte conclusie: -->
## 9. Conclusie

De uitrol van de omgeving verloopt grotendeels succesvol. Grote componenten werken (AD, DNS, DHCP, firewall). De resterende punten (CA, MSSQL-service) zijn deels functioneel en kunnen handmatig aangepast worden.

**Geleerd:**

* Idempotentie is cruciaal bij provisioning van meerdere servers.
* Kleine scripts eerst testen voorkomt lange troubleshooting.
* Hoe zwaar het is om Windows server te automatiseren via vagrant. (vagrant meer gemaakt voor Linux).

**Toekomstige verbeteringen:**

* Provisioning splitsen in kleinere, onafhankelijke scripts per functie.
* Meer testen van individuele scripts voor volledige functionaliteit.
* Handmatige controles en logging verbeteren bij services zoals MSSQL en CA.

**verloren tijd**
<!-- - Aan welke zaken heb je (te) veel tijd verloren? -->
ik heb te veel tijd verloren aan het laten uitvoeren van de scripts met 1 vagrant run, door meerdere provisionings te doen in & run.
 - hierbij ben ik op veel fouten terecht gekomen met rebooten.