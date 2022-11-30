# Auto-Recon
Auto-Recon is an **automated web reconnaissance platfom**  written in python. The goal of Auto-Recon is to provide an **overview** of the target in a **short** amount of time while maintaining the **accuracy** of results. Instead of executing **several tools** one after another it can provide similar results keeping dependencies **small and simple**.
## Features
* Header Information 
* Whois
* DNS Enumeration
    * A, AAAA, CNAME, MX, NS, SOA, TXT Records
* Port scan 
## Installation
### Linux Installation
```bash
git clone https://github.com/3ifa/Auto-Recon.git
cd Auto-Recon
pip install requirements.txt
python3 app.py
```
### Docker 
```bash
docker build -t Auto-Recon:latest
docker run -dp 80:80 Auto-Recon:latest
```