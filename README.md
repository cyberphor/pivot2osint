# pivot2osint
> Automates malware hashing and pivoting to OSINT data sources for additional values of interest.

## Installation
```bash
git clone https://github.com/cyberphor/pivot2osint.git 
chmod 754 ./pivot2osint/pivot2osint.py
sudo mv ./pivot2osint/pivot2osint.py /usr/local/bin/
```

## Usage
```bash
tshark -nr traffic.pcap --export-objects http,evidence
cd evidence

pivot2osint.py --virus-total # option 1
pivot2osint.py --team-cymru # option 2
```

## Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
