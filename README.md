# Sustav za edukaciju i trening SOC analitičara

Ovaj projekt predstavlja nadogradnju diplomskog rada *"Sustav za edukaciju i trening analitičara u sigurnosnim operativnim centrima"*, izrađenog na Fakultetu elektrotehnike i računarstva. Cilj projekta je omogućiti simulaciju stvarnih napada putem računalnih zapisa i njihovu analizu u okruženju alata Splunk.

## Struktura projekta

```bash
├── docker-compose.yml              # Definicija servisa (splunk-server, splunk-uf, rabbitmq, parser-app, log-sender)
├── parser_app/                     # Folder za parser_app servis
│   ├── Dockerfile                  # Dockerfile za parser_app
│   └── parser_app.py               # CLI-aplikacija za obradu placeholder logova i slanje u RabbitMQ
├── log_sender/                     # Folder za log_sender servis
│   ├── Dockerfile                  # Dockerfile za log_sender
│   └── log_sender.py               # Skripta za preuzimanje iz RabbitMQ i dostavu logova (UDP/TCP/UF)
├── splunk_config/                  # Konfiguracija za Splunk Universal Forwarder
│   ├── inputs.conf                 # Definicija inputa za Splunk Universal Forwarder
│   └── outputs.conf                # Definicija outputa za Splunk Universal Forwarder
├── splunkuf/                       # Mapa za Splunk Universal Forwarder
│   └── splunkUF.txt                # Log datoteka koju prati Splunk UF
├── Logovi/                         # Mapa s JSON predlošcima logova s placeholderima
│   ├── Prvi/                       # Prva kategorija napada (Brute Force, Connection, Noise...)
│   └── Drugi/                      # Druga kategorija napada (Privilege Escalation, Email, Web Server...)
└── inputs.conf                     # Definicija inputa za Splunk Enterprise
```

## Osnovni tijek rada

1. **Pre-generiranje (pre-parse)**

   * Skripte u mapi `Logovi` sadrže neobrađene zapise s placeholderima (npr. `{{NOW+X}}`, `{{HOST_1}}`, `{{USER_1}}`).
   * Ovaj korak priprema skupove JSON zapisa za daljnju obradnu.

2. **parser\_app**

   * Smješten u mapi `parser_app/` s pripadajućim `Dockerfile`-om.
   * Učitava željene JSON predloške prema konfiguraciji (naredbom `set`).
   * Zamjenjuje placeholder vrijednosti (IP adrese, korisnička imena, portove, PID-ove, relativno vrijeme) stvarnim vrijednostima.
   * Šalje poruke u RabbitMQ s poljem `delay_seconds`, linijom zapisa (`line`) i odabranim protokolom (`udp`, `tcp` ili `uf`).
   * CLI podržava naredbe:

     * `help` – popis dostupnih naredbi
     * `set`  – konfiguracija kategorija napada, protokola i brzine
     * `show` – prikaz trenutne konfiguracije
     * `start` – stavljanje svih pripremljenih poruka u red
     * `stop`  – prekid trenutnog slanja
     * `exit`  – izlaz

3. **RabbitMQ**

   * Služi kao međuspremnik između `parser_app` i `log_sender` servisa.

4. **log\_sender**

   * Smješten u mapi `log_sender/` s pripadajućim `Dockerfile`-om.
   * Čeka poruke iz RabbitMQ reda (`log_queue`).
   * Za svaku poruku čita `delay_seconds` i čeka traženo kašnjenje relativno od zadnjeg zapisa.
   * Dostavlja log:

     * UDP: direktno Splunku (`DEST_HOST:UDP_PORT`)
     * TCP: Splunk tramite TCP (`DEST_HOST:TCP_PORT`)
     * UF: zapisuje u datoteku `splunkUF.txt` u mapi `splunkuf/`, koju prati Splunk Universal Forwarder.

5. **Splunk Enterprise**

   * Konfiguriran pomoću `inputs.conf`.
   * Prima logove preko UDP, TCP ili SplunkUF i indexira ih za vizualizaciju.

6. **Splunk Universal Forwarder (UF)**

   * Čita datoteku `splunkuf/splunkUF.txt`.
   * Prosljeđuje zapise prema Splunk Enterprise.

## Pokretanje u Dockeru

1. **Build i podizanje servisa**

   ```bash
   docker-compose up --build -d
   ```

2. **Pokretanje parser\_app unutar kontejnera**

   ```bash
   docker-compose exec -it parser-app python parser_app.py
   ```

## Kratak opis sekcija

* **`parser_app/`**: Aplikacija za punjenje placeholdera i objavljivanje logova s vremenskim kašnjenjem.
* **`log_sender/`**: Zadaća mu je preuzeti poruke iz reda, pričekati definirano kašnjenje i poslati liniju zapisa prema odabranom protokolu.
* **`splunk_config/`**: Konfiguracijski fajlovi za Splunk Universal FOrwarder (`inputs.conf`).
* **`splunkuf/`**: Mapa za Splunk Universal Forwarder s log datotekom `splunkUF.txt`.
* **`Logovi/Prvi` i `Logovi/Drugi`**: JSON predlošci napada razvrstani po kategorijama.
* **`docker-compose.yml`**: Definira servise:

  * **`splunk-server`** – Splunk za indeksiranje i vizualizaciju logova
  * **`splunk-uf`** – Universal Forwarder za preuzimanje logova iz datoteke
  * **`rabbitmq`** – Message broker
  * **`parser-app`** – Aplikacija za pripremu i slanje poruka
  * **`log-sender`** – Aplikacija za isporuku logova
