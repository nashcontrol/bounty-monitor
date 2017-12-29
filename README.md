# Bounty Monitor
Leverage certificate transparency live feed to monitor for newly issued subdomain cerficates, for domains participating in bug bounty programs
### Installation
The script was tested on Python2.7

Clone repo and install packages:

```sh
git clone https://github.com/nashcontrol/bounty-monitor.git
pip install -r requirements.txt
```

### Usage
```
python bounty-monitor.py
```

### Analyze the results
Log file created with all subdomains found subdomains to `all_subdomains.log` and ones that are live to `live_subdomains.log`

Subdomain database `subdomains.db` is initaillized and maintained locally to keep track of identified live and known subdomains.

## Inspired by
1. [bucket-stream](https://github.com/eth0izzle/bucket-stream) - Find interesting Amazon S3 Buckets
2. [phishing_catcher](https://github.com/x0rz/phishing_catcher) - Catching malicious phishing domain names

License
----
MIT
