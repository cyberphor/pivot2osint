# pivot2osint
> Automates malware hashing and pivoting to OSINT data sources for additional values of interest.

## Installation
```bash
git clone https://github.com/cyberphor/pivot2osint.git 
chmod 754 ./pivot2osint/pivot2osint.py
sudo cp ./pivot2osint/pivot2osint.py /usr/local/bin/pivot2osint
```

## Usage
```bash
wget https://www.malware-traffic-analysis.net/2014/11/23/2014-11-23-traffic-analysis-exercise.pcap.zip
unzip 2014-11-23-traffic-analysis-exercise.pcap.zip
mv 2014-11-23-traffic-analysis-exercise.pcap.zip traffic.pcap
tshark -nr traffic.pcap --export-objects http,evidence
cd evidence
```
```bash
# option 1
pivot2osint --virus-total

# option 2
pivot2osint --team-cymru
```

## Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
