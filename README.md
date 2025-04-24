# Sustav za edukaciju i trening SOC analitičara

Ovaj projekt predstavlja nadogradnju diplomskog rada *"Sustav za edukaciju i trening analitičara u sigurnosnim operativnim centrima"*, izrađenog na Fakultetu elektrotehnike i računarstva. Cilj projekta je omogućiti simulaciju stvarnih napada putem računalnih zapisa i njihovu analizu u okruženju alata Splunk.

## Struktura sustava

- Python aplikacija (`SOCPRO3.py`) omogućuje konfiguraciju i slanje različitih vrsta logova
- Splunk Universal Forwarder koristi se za prijenos podataka u Splunk server
- Splunk server omogućuje prikupljanje, indeksiranje i vizualizaciju logova
- Docker okruženje osigurava jednostavno pokretanje i upravljanje svim komponentama

### Struktura projekta

```
.
├── Dockerfile
├── docker-compose.yml
├── SOCPRO3.py
├── splunk_config/
│   ├── inputs.conf
│   └── outputs.conf
├── Logovi_za_prikaz/
├── Drugi_napad_logovi/
└── test_copy_paste.txt
```

## Pokretanje sustava

### 1. Build i pokretanje kontejnera

U korijenskom direktoriju projekta potrebno je pokrenuti:

```
docker-compose down -v
docker-compose up --build
```

### 2. Otvaranje Splunk sučelja

Nakon pokretanja kontejnera, Splunk sučelje dostupno je na:

- Otvorite http://localhost:8000
- Prijavite se s korisničkim imenom i lozinkom definiranim u `docker-compose.yml` (`admin` / `Mojasifra123!`)

### 3. Unos naredbi za napade

Unutar `python-app` kontejnera pokreće se aplikacija pomoću naredbi:

```
docker exec -it python-app bash
python SOCPRO3.py
```

Primjer naredbe za konfiguraciju napada:

```
{"command": "SET", "params": [ {"variable": "splunkUF", "value": true}, {"variable": "protocol", "value": "tcp"}, {"variable": "brute_force_connection", "value": true}, {"variable": "connection", "value": true}, {"variable": "EmailLogs", "value": true}, {"variable": "malicious_ip", "value": "192.168.1.100"} ]}
```

Pokretanje:

```
{"command": "START"}
```

Ostale naredbe:

```
{"command": "STOP"}
{"command": "HELP"}
{"command": "EXIT"}
```