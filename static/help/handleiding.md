# Handleiding DomainLens

DomainLens bewaakt de domeinen van een organisatie op twee manieren: **beveiliging** (mail, DNS, TLS, webheaders, kwetsbare software, reputatie) en **registratie** (bij welke registrar, tot wanneer, in quarantaine of niet). Deze handleiding legt per scherm uit wat je ziet en hoe je het gebruikt. Technische details en de API staan in `docs/USAGE.md` in de repository.

> De interface is er in het Engels en het Nederlands (**Admin → Settings → General → Language**). Deze handleiding noemt de menunamen zoals ze in het Engels heten, met de Nederlandse naam erachter waar die anders is: **Monitoring → Domain changes** (Domeinwijzigingen).

## Hoe DomainLens rapporteert

Elke uitkomst valt in een van drie toestanden, en DomainLens houdt die bewust uit elkaar:

| Toestand | Betekenis | Voorbeeld |
|---|---|---|
| Gemeten | Er is gekeken en dit is het antwoord | "DMARC staat op reject", "Has the fix" |
| Niet gemeten | Er kon niet gekeken worden: geen antwoord, een time-out, een limiet van een externe dienst | "Not measured", "No response", "Could not be measured" |
| Niet van toepassing | De vraag geldt hier niet | DANE voor een domein dat geen mail ontvangt |

Een uitkomst die niet gemeten is, telt nooit als goed en nooit als fout. Zie je "niet gemeten", dan zegt dat iets over de meting (bijvoorbeeld een DNS-server die niet antwoordde), niet over het domein.

### De rating A+ tot F

Elk domein krijgt een letter op basis van de **open bevindingen** van zijn laatste scan. Geaccepteerde risico's tellen niet mee.

| Rating | Open bevindingen |
|---|---|
| A+ | geen (hooguit notities) |
| A | alleen laag |
| A- | een of twee middel, niets ergers |
| B | drie of meer middel, niets ergers |
| C | een of twee hoog, niets kritieks |
| D | drie of meer hoog, niets kritieks |
| F | minstens één kritiek |

Grafieken tellen A+, A en A- samen als A. De TLS-grade (A+ tot F op het tabblad SSL/TLS) is iets anders: die beschrijft alleen de TLS-instellingen.

## Snel aan de slag

1. **Zet je domeinen in het portfolio.** Ga naar **Monitoring → Domain portfolio** (Domeinportfolio), open **Add domains** en plak een lijst (`example.nl;Verkoop`) of kies een CSV- of Excelbestand. Zie [Domeinportfolio](#domeinportfolio).
2. **Richt de organisatie in.** Onder **Monitoring → Organisation** (Organisatie) maak je bedrijven en afdelingen, met per eenheid een contactpersoon en de registrar waar de domeinen horen. Zie [Organisatie](#organisatie).
3. **Zet beveiligingsmonitoring aan.** Kies in het portfolio bij een eenheid **Monitoring → daily**, of selecteer domeinen en kies **Monitoring ▾**. Elke monitor scant het domein volgens schema.
4. **Controleer dat de scheduler aanstaat.** Staat er onder het menu "The scheduler is off", dan gebeurt er niets vanzelf. Zet hem aan onder **Admin → Settings**. Zie [Als er niets vanzelf gebeurt](#als-er-niets-vanzelf-gebeurt).
5. **Lees het resultaat.** **Reports → Dashboard** laat zien hoe alles ervoor staat; klik op een getal of balk om de domeinen erachter te zien. Wijzigingen staan onder **Monitoring → Monitor events** en **Monitoring → Domain changes**.

## Rollen en inloggen

| Rol | Mag |
|---|---|
| Viewer | Alles lezen: scans, rapporten, monitors, trends. Verandert niets |
| Analyst | Daarnaast scannen, monitors beheren, het portfolio en de organisatie wijzigen, importeren |
| Admin | Daarnaast instellingen, gebruikers, koppelingen, geaccepteerde risico's, kwetsbaarheidsregels en het auditlog |

Inloggen kan met een lokaal account of via single sign-on (Microsoft Entra ID, SAML), afhankelijk van hoe de beheerder het heeft ingericht. Onder **Account** stel je je wachtwoord, tweestapsverificatie (MFA) en persoonlijke API-tokens in. Elke wijziging die iemand doet, staat in het auditlog.

## Het menu

| Menu | Wat je er doet |
|---|---|
| **Scan** | Eén domein nu scannen en het resultaat lezen |
| **Tools** | Losse opzoekingen: WHOIS, IP-adres, DNS-record, imitatie, disclosure, mail en links, softwareversies |
| **Monitoring** | Monitors, hun meldingen, het domeinportfolio, de wijzigingen daarin en de organisatie |
| **Reports** (Rapporten) | Scangeschiedenis, dashboard, trends en vergelijken |
| **Remediation** (Herstel) | Per domein wat er moet gebeuren en hoe je het hertest |
| **Help** (Handleiding) | Deze handleiding |
| **Admin** | Instellingen, gebruikers, geverifieerde domeinen, geaccepteerde risico's, kwetsbaarheidsregels, auditlog |

Elke pagina heeft een eigen adres. Filters staan in het adres, dus een gefilterde lijst kun je als bladwijzer bewaren of als link naar een collega sturen.

## Scan

Vul een domein in (`example.nl`) en kies **Scan**. Laat **All checks** aan voor een volledige scan, of kies losse onderdelen. Het resultaat staat in tabbladen:

- **Advies**: elke bevinding met het probleem, hoe je het oplost en hoe je het hertest. Kritiek, hoog en middel staan bovenaan.
- **Security Audit**: webbeveiliging (headers, CSP, cookies, CORS), JavaScript-bibliotheken en gelekte sleutels, versies die de server toont.
- **WHOIS**, **DNS**, **E-mail** (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DANE), **SSL/TLS** (grade, NCSC-richtlijnen), **Web**, **Network**, **OSINT** (certificaattransparantie, dreigingsfeeds, reputatie).

Naast de titel staat de rating. Onder de kop van het resultaat zet **Add to unit** het domein in een eenheid van de organisatie. **Report** opent een printbaar rapport (afdrukken of opslaan als pdf); het menu **Export** geeft JSON, Markdown of CSV.

> Een scan die een site niet kan bereiken (time-out, geoblokkade, poort dicht) meldt "niet gemeten". Dat is geen bevinding over het domein. Scan opnieuw, of controleer het vanaf een andere plek.

### Een risico accepteren

Een bevinding die je bewust laat staan, accepteert een beheerder met **Accept risk…** onder de bevinding: met een reden, een eigenaar en een einddatum. Een geaccepteerd risico telt niet meer mee voor de rating. Na de einddatum telt het weer.

## Tools

### WHOIS

**Tools → WHOIS** zoekt de registratie van één domein op: status, registrar, reseller, DNSSEC, nameservers en data. Een subdomein wordt opgezocht bij zijn geregistreerde domein. Voor `.nl`, `.be`, `.de`, `.eu` en `.at` publiceert het register geen verloopdatum: dat staat er als "Not published", niet als "onbekend".

**Batch lookup** op dezelfde pagina zoekt een lijst op (tot 500 domeinen) en levert een CSV. **Add as wanted domain** zet een domein dat je wilt hebben in het portfolio met het besluit "Request or claim".

### IP-adres

**Tools → IP address** laat zien bij welk netwerk een adres hoort, waar het staat, en of het op een blokkadelijst of dreigingslijst staat. **My IP address** vult je eigen adres in.

### DNS-record

**Tools → DNS record** stelt één vraag aan een resolver. **Propagation check** stelt dezelfde vraag aan meerdere resolvers en vergelijkt de antwoorden: *propagated* (iedereen geeft hetzelfde), *inconsistent* (de antwoorden verschillen, de wijziging rolt nog uit) of *unknown* (te weinig antwoorden om te vergelijken). Een resolver die niet antwoordt, staat er als *unreachable*.

### Imitatie

**Tools → Impersonation** (Imitatie) maakt een dossier over een domein dat het jouwe nadoet: registrar, hostingnetwerk en waar je het meldt. DomainLens legt de feiten vast; de beoordeling dat het inbreuk maakt, blijft bij jou.

### Disclosure

**Tools → Disclosure** controleert de `security.txt` en de PGP-sleutel van een domein, valideert een geplakte `security.txt` of sleutel, en maakt een sleutelpaar aan zonder iets te bewaren.

### Mail en links

**Tools → Mail & web** heeft twee tabbladen:

- **Message or file**: upload een ontvangen bericht (`.eml` of Outlook `.msg`) of een bijlage. DomainLens controleert SPF, DKIM en DMARC, de verzendende server, de inhoud, de links en de bijlagen. Niets wordt geopend of uitgevoerd, en alleen hashes verlaten de server.
- **Links**: plak een of meer verdachte links. Een link wordt nooit geopend; hij wordt beoordeeld op hoe hij eruitziet, of hij een van je eigen domeinen nadoet, en wat er bekend over is.

### Versies

**Tools → Versions** (Versies) controleert of je sites een softwareversie met een bekende ernstige kwetsbaarheid tonen. Kies alle domeinen uit het portfolio, één eenheid, of plak domeinen.

| Uitkomst | Betekenis |
|---|---|
| Vulnerable | De getoonde versie is ouder dan de versie met de oplossing |
| Cannot tell from outside | De software is in gebruik, maar de versie is verborgen of het is een build van een distributie |
| Has the fix | De getoonde versie bevat de oplossing |
| Not affected | De versie is ouder dan de fout |
| None of the software seen | Niets in het antwoord wijst op de software waar de regels naar zoeken |
| No response | De site antwoordde niet |
| No website in DNS | Het domein en `www.` hebben geen adres: er is geen website |
| Not checked | Het domein wijst naar een adres binnen een netwerk |

**Details** onder elke rij laat zien hoe de uitkomst tot stand kwam: wat DNS zei, welke adressen zijn opgevraagd, en elke stap van een doorverwijzing. Verwijst een domein door naar een ander domein, dan staat de server van dat andere domein er apart onder (**Redirects to ...**): die versie hoort bij dat domein, niet bij dit. **Export CSV** geeft de tabel aan het team dat moet patchen.

## Monitoring

### Monitors

Een monitor scant een domein of host volgens schema en vergelijkt elke scan met de vorige. Onder **Monitoring → Monitors**:

- **Add monitors** maakt een monitor: domein of host, eventueel een eenheid, de frequentie, een tijdstip ("om 03:00") en het DNS-record dat bewaakt wordt (A voor een website, MX voor mail, CNAME voor een host die ergens anders naar wijst).
- **Plan all scans** geeft alle monitors een eigen tijdstip, een paar minuten na elkaar, zodat ze niet allemaal tegelijk draaien.
- **Run due** draait nu alle monitors die aan de beurt zijn.
- **Discovered hostnames** toont hostnamen die in certificaatlogboeken zijn gezien onder een domein dat je al bewaakt; vink ze aan om ze ook te bewaken of te verbergen.

Onder de lijst staan de laatste vijf meldingen. Alle meldingen, met filters, staan onder [Monitor-events](#monitor-events).

### Monitor-events

**Monitoring → Monitor events** (Monitor-events) is de lijst van alles wat de monitors gevonden hebben.

| Soort | Betekenis |
|---|---|
| Changed | Iets is anders dan bij de vorige scan |
| Scan failed | De scan lukte niet |
| DNS did not answer | De nameservers van het domein antwoordden niet, ook niet na herhaalde pogingen |
| Baseline | De eerste scan: het vergelijkingspunt, geen wijziging |
| No change | De scan vond niets nieuws |

**Filteren.** Zoek op host, label of tekst; kies een monitor, een eenheid of een periode (7 dagen tot alles, of eigen data); en klik op de knoppen bij **Kind** en **Severity** om op soort en ernst te filteren. Elke knop zegt hoeveel meldingen hij zou tonen. Bij openen staat "No change" uit, zodat je ziet wat er gebeurd is; klik erop om die meldingen ook te zien. Klik op een host om alleen die monitor te zien. **Clear filters** zet alles terug.

**Wat is er veranderd?** Bij een wijziging opent **What changed?** de vergelijking van de twee scans: de velden die bewogen, de bevindingen die erbij kwamen of verdwenen, en het DNS-record dat de monitor bewaakt (bijvoorbeeld `192.0.2.10 → 192.0.2.11`).

> Staat er bij een oudere melding "The comparison shows no difference", dan komt die uit de eerdere manier van wijzigingen detecteren, die ook waarden telde die bij elke scan verschillen. Zulke meldingen worden niet meer gemaakt. Je kunt ze verwijderen.

**Verwijderen.** Een melding die onterecht was (bijvoorbeeld door een storing aan de kant van de scanner) vink je aan en verwijder je met **Delete selected**. Het rapport waar hij naar verwijst blijft bestaan; de verwijdering staat in het auditlog.

### Domeinportfolio

**Monitoring → Domain portfolio** (Domeinportfolio) bevat de domeinen die je hebt, per eenheid. Elk domein wordt bij het register opgezocht: dagelijks, elke zes uur in de maand voor het verloopt, en elk uur terwijl het verwijderd wordt.

**Domeinen toevoegen.** Open **Add domains** en plak een domein per regel, eventueel met een eenheid (`example.nl;Verkoop`, of een pad: `example.nl;Bedrijf X > Verkoop`; ontbrekende niveaus worden gemaakt). Of kies een CSV-, tekst- of Excelbestand. Met een kopregel worden alleen de genoemde kolommen gelezen:

| Kolom | Ook herkend als | Inhoud |
|---|---|---|
| Domain | Domein, URL, Website | Het domein (een subdomein of adres wordt het geregistreerde domein) |
| Unit | Company, Bedrijf, Eenheid, Afdeling | De eenheid |
| Decision | Besluit | Keep, To decide, Cancel, Request or claim (ook in het Nederlands) |
| Contact | Contactpersoon, Owner, Eigenaar | Een naam, e-mailadres of "Naam <adres>" |
| E-mail | | Het adres van de contactpersoon |
| Threat intel | | ja of nee |

**Bijwerken met een import.** Een domein dat er al staat, wordt bijgewerkt: exporteer met **Download CSV**, pas een besluit aan of zet threat intel op ja, en importeer het bestand opnieuw. Kolommen die DomainLens zelf meet (fase, registrar, mail, web) worden niet gelezen. Het resultaat laat per domein zien wat er van wat naar wat veranderde, en welke waarden niet gebruikt konden worden. Een lege cel verandert niets.

**De lijst.** Elke rij toont de monitoring, de registratie (registrar, reseller, verloopdatum, en **To move** als het domein bij een andere registrar staat dan de eenheid verwacht), de status, het gebruik (✉ mail en 🌐 web; doorgestreept als gemeten ongebruikt, gestippeld als niet gemeten), threat intel, het besluit en de contactpersoon. Het menu ⋯ aan het eind van een rij verplaatst, bewaakt, zoekt opnieuw op of verwijdert. De tegels bovenaan filteren de lijst.

**Meerdere domeinen tegelijk.** Vink domeinen aan (of een hele eenheid) en gebruik de balk die verschijnt: **Move to unit**, **Monitoring**, **Decision**, **Threat intel**, **Contact**. Elke keuze wordt direct toegepast, met **Undo** om het terug te draaien.

**Besluit.** Elk domein heeft een besluit, en de waarschuwingen volgen dat besluit:

| Besluit | Betekenis | Waarschuwingen |
|---|---|---|
| Keep and renew (standaard) | Het domein blijft | Alles: verlopen, quarantaine, wissel van registrar of nameservers, te verhuizen |
| To decide | De toekomst is nog open | Als bij Keep |
| Cancel (let it lapse) | Het domein wordt opgezegd | Verlopen is het plan: geen verloopwaarschuwingen; een wissel van registrar blijft belangrijk |
| Request or claim | Nog niet van jou: aanvragen zodra het vrij is | Vrijkomen is het nieuws ("can be requested now") |

**Threat intel** geeft aan of het domein bij je threat-intelligence-dienst is aangemeld. Een domein dat in gebruik is (mail of web) en niet is aangemeld, krijgt de markering "In use, no threat intel".

**Contactpersoon.** Een domein heeft de contactpersoon van zijn eenheid, tenzij je met **Link contact** een eigen koppelt.

Alle wijzigingen van de domeinen staan onder [Domeinwijzigingen](#domeinwijzigingen).

### Domeinwijzigingen

**Monitoring → Domain changes** (Domeinwijzigingen) is de lijst van elke wijziging van de domeinen in het portfolio:

- wat het register liet zien: een andere **registrar**, **reseller** of **nameservers**, een andere **fase** (quarantaine, verwijderd, niet meer geregistreerd), een **verloopdatum** die dichtbij komt, nameservers die niet meer antwoorden;
- wat iemand veranderde, met de hand of met een import: het **besluit**, **threat intel**, de **contactpersoon**, de **eenheid**, en domeinen die zijn **toegevoegd** of **verwijderd**.

Elke regel toont wanneer, het domein, de eenheid, wat er veranderde, de oude waarde (doorgestreept) en de nieuwe, en wie het deed: **Registry lookup**, **Changed by hand** (met het account) of **Import**.

**Filteren.** Zoek op domein, waarde of persoon (bijvoorbeeld de naam van een registrar); kies een eenheid of periode; en klik op de knoppen bij **What** en **Found by**. Klik op een domein of eenheid in de lijst om daarop te filteren. **Download CSV** levert precies de gefilterde lijst.

> De eerste opzoeking van een domein is het vergelijkingspunt, geen wijziging. Wijzigingen met de hand en via een import worden bijgehouden vanaf versie 0.1.18; wat daarvoor met de hand is veranderd, staat alleen in het auditlog.

### Organisatie

**Monitoring → Organisation** (Organisatie) ordent de domeinen in bedrijven en de eenheden daaronder (`Bedrijf X › Retail › Webshop`), met per eenheid beide soorten monitoring: beveiliging (rating, open kritieke en hoge bevindingen, monitors en meldingen) en registratie (domeinen in gevaar, bijna verlopen, te verhuizen). De cijfers van een eenheid tellen de eenheden eronder mee.

- **Add a company or business unit** maakt een eenheid, eventueel onder een andere.
- Een eenheid kan de **registrar** noemen waar haar domeinen horen. Eenheden eronder nemen die over, tenzij ze een eigen noemen. Een domein elders krijgt **To move**.
- **Contacts** beheert de contactpersonen. Koppel een contactpersoon aan een eenheid; eenheden en domeinen eronder nemen die over.
- **Edit, move or merge units** hernoemt, verplaatst of voegt eenheden samen; **Delete unit** verwijdert er een (je kiest wat er met de inhoud gebeurt).
- **Notify** geeft een eenheid eigen meldadressen: meldingen over haar domeinen gaan dan ook naar die adressen, en naar die van de eenheden erboven.

Klik op een eenheid voor haar eigen pagina: de cijfers, de eenheden en domeinen eronder, haar monitors, de meest voorkomende risico's en de recente wijzigingen. Daar wijzig je ook de contactpersoon, en zet je met **Monitor security of all domains** monitors aan voor elk domein dat er nog geen heeft.

## Rapporten

### Scangeschiedenis

**Reports → Scan history** (Scangeschiedenis) toont alle bewaarde scans. Open een rapport, verwijder een scan, of vink er twee aan en kies **Compare** voor een overzicht van wat er tussen die twee scans veranderde.

### Dashboard

**Reports → Dashboard** laat zien hoe alle domeinen ervoor staan, voor wie geen scanrapporten leest: hoeveel er in orde zijn (A of B), de open kritieke en hoge bevindingen, welke basismaatregelen op orde zijn, de risico's die de meeste domeinen raken, welke domeinen eerst aandacht nodig hebben, en wat beter of slechter werd. Kies 30 dagen, 90 dagen of een jaar, en eventueel één eenheid. **Print / PDF** drukt het af als rapport.

**Klik voor de domeinen erachter.** Elk getal, elke balk en elke rating is aanklikbaar:

| Klik op | Je ziet |
|---|---|
| Een tegel (domeinen, in orde, kritiek, hoog, geaccepteerd) | De domeinen die dat getal vormen |
| Een rating in de legenda | De domeinen met die rating |
| Een basismaatregel | Per domein: in orde, ontbreekt, of niet gemeten (die laatste telt nergens mee) |
| Een risico onder "Most common risks" | De domeinen met die bevinding |
| Een gebied onder "Findings by area" | De domeinen met bevindingen in dat gebied, met de bevindingen zelf |

De lijst opent onder de kaart waarop je klikte, met per domein de rating, de eenheid, de scandatum en een link naar het rapport. **Copy domains** kopieert de domeinnamen, bijvoorbeeld voor een ticket. De keuze staat in het adres: een link opent hetzelfde overzicht met dezelfde lijst.

### Trends

**Reports → Trends** is voor wie de scans draait: activiteit en scores over 7, 30 of 90 dagen, eventueel voor één domein.

- Een **tegel** opent de lijst erachter (scans, domeinen, wat bewoog in issues, TLS- en headerscores, blacklist, ServiceNow-incidenten).
- Een **dag in een grafiek** opent wat die grafiek telt, op die dag: bij *Issues over time* en *TLS / header scores* de scans van die dag met het verschil ten opzichte van de vorige scan van hetzelfde domein; bij *Scan volume* de scans; bij *Event severity* de monitor-events van die dag.
- **What changed?** in zo'n lijst vergelijkt de scan met de vorige.
- Een domein onder **Noisiest domains** filtert de hele pagina op dat domein.

### Vergelijken

**Reports → Compare** (Vergelijken) vergelijkt één domein tussen twee periodes, veld voor veld: SPF van `-all` naar `~all`, DMARC van reject naar none, een lagere TLS-grade, een header die verdween. Elke periode wordt vertegenwoordigd door haar laatste scan; beide scans staan onder het resultaat. Een onderdeel dat maar in één van de twee scans zat, staat onder "could not be compared", nooit onder "niets veranderd".

## Herstel

**Remediation** (Herstel) geeft per domein het herstelplan uit de laatste scan: wat er moet gebeuren, op volgorde van ernst, en hoe je het daarna hertest. Kies een domein uit **Recently scanned**. Deze pagina's zijn ook het doel van de links vanuit ServiceNow.

## Beheer

Alleen voor beheerders, onder **Admin**:

- **Settings**: algemeen (naam, taal), scan (eigen resolvers), meldingen (e-mail, Slack, Teams, webhook en de minimale ernst), de scheduler, koppelingen (ServiceNow, Rapid7, Entra ID, SCIM), API-sleutels van externe diensten en hun limieten, IP-dreigingslijsten, mailanalyse, je eigen `security.txt` en PGP-sleutel, tests van eigen infrastructuur, en **Backup** (een kopie van de database downloaden).
- **Users**: accounts, rollen en API-tokens.
- **Verified domains**: domeinen waarvan bewezen is dat ze van jou zijn. Alleen die worden actief getest (zwakke wachtwoorden, actieve scan).
- **Accepted risks**: de geaccepteerde risico's, met reden, eigenaar en einddatum.
- **Vulnerability rules**: regels voor kwetsbare softwareversies, die zonder nieuwe versie van DomainLens toe te voegen zijn. **Test** probeert een regel op geplakte headers.
- **Audit log**: wie wat wanneer deed.

## Meldingen

DomainLens stuurt wijzigingen naar de kanalen onder **Admin → Settings → Notifications**: e-mail, Slack, Teams of een webhook, vanaf een ingestelde ernst. Meldingen over een eenheid gaan daarnaast naar de adressen van die eenheid (zie [Organisatie](#organisatie)). Met ServiceNow gekoppeld worden hoge en kritieke meldingen een incident; het nummer staat bij de melding onder **Monitor events**.

## Problemen oplossen

### Als er niets vanzelf gebeurt

Monitors, opzoekingen in het portfolio en gewenste domeinen draaien alleen als de scheduler aanstaat. Staat hij uit, dan zegt de balk onder het menu waarom: uitgezet in **Admin → Settings** (met een link) of voor de hele server met `DOMAINLENS_DISABLE_SCHEDULER`. Met de scheduler uit kun je een domein met de hand opnieuw opzoeken via ⋯ → **Look up again now**, en monitors draaien met **Run due**.

### "Niet gemeten" of "No response"

Er kon niet gemeten worden: een DNS-server of site antwoordde niet, of een externe dienst had zijn limiet bereikt. Probeer het later opnieuw. Antwoordt de DNS van de server zelf niet, dan wachten alle scans tot hij weer antwoordt, en zegt de monitorpagina sinds wanneer.

### Een wijziging zonder verschil

Toont **What changed?** bij een oudere melding niets, dan komt die melding uit de eerdere manier van detecteren. Nieuwe meldingen zeggen altijd wat er veranderde, ook als het alleen het bewaakte DNS-record is.

### Een domein zonder website

Onder **Tools → Versions** krijgt een domein zonder adres in DNS de uitkomst **No website in DNS**. Dat is geen fout: er is geen site om te controleren.

### Een vertaling ontbreekt

Tekst die nog niet vertaald is, blijft Engels, nooit leeg. Gegevens van buiten (antwoorden van registers, headers, namen van cipher suites) blijven zoals ze binnenkomen. Exports, e-mails en meldingen zijn in het Engels.

## Woordenlijst

| Woord | Betekenis |
|---|---|
| Baseline | De eerste meting: het vergelijkingspunt, geen wijziging |
| Bevinding | Iets wat een scan vond, met een ernst (kritiek, hoog, middel, laag, info) |
| Eenheid | Een bedrijf, bedrijfsonderdeel of afdeling in de organisatie |
| Monitor | Een scan die volgens schema herhaald wordt |
| Event (melding) | Wat een monitor vond: een wijziging, een mislukte scan, een eerste scan |
| Quarantaine | Een opgezegd `.nl`-domein dat nog 40 dagen alleen door de oude houder terug te halen is |
| Registrar | Het bedrijf waar een domein is geregistreerd |
| Reseller | De partij die het domein via de registrar verkoopt |
| Scheduler | Het onderdeel dat monitors en opzoekingen vanzelf laat draaien |
| Threat intel | Een dienst die waarschuwt voor misbruik van je domeinen (bijvoorbeeld phishing) |
