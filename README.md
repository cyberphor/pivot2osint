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

# output
[+] Pivoting to VirusTotal with 163 values of interest (ETA: 40 minutes, 12:44:52).
 --> 1/58 878c0014e7a5eb63ac27c125a6bbc4a8 &rp_s=c&kw=Hijinksensue.com&tg_i.Site=Hijinksensue.com&p_pos=btf&p_screen_res=1440x900
 --> 11/59 39c4b9865714d20f570636a4072d85a0 jquery.js%3fver=1.11.1
 --> 49/67 1408275c2e2c8fe5e83227ba371ac6b3 cars.php%3fhonda=1185&proxy=2442&timeline=4&jobs=823&image=171&join=757&list=679
 --> 3/58 369ff395a3bca47925285dcac744be22 birds.php%3fwinter=3
```
```bash
# option 2
pivot2osint --team-cymru

# output
[+] Pivoting to Team Cymru with 163 values of interest.
 --> 21 d41d8cd98f00b204e9800998ecf8427e cw_match
 --> 33 1408275c2e2c8fe5e83227ba371ac6b3 cars.php%3fhonda=1185&proxy=2442&timeline=4&jobs=823&image=171&join=757&list=679
```

## Copyright
This project is licensed under the terms of the [MIT license](/LICENSE).
