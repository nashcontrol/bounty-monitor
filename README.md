# Bounty Monitor
Leverage certificate transparency live feed to monitor for newly issued subdomain certificates (last 90 days, configurable), for domains participating in bug bounty programs.

![Demo](https://i.imgur.com/VpetOcb.png)

### Installation
The script was tested on Python2.7 and python3.6

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
Log file created with all found subdomains to `all_subdomains.log` and ones that are live and aged less than 90 days to `live_subdomains.log`

Subdomain database `subdomains.db` is initialized and maintained locally to keep track of identified live and known subdomains.

## Inspired by
1. [bucket-stream](https://github.com/eth0izzle/bucket-stream) - Find interesting Amazon S3 Buckets
2. [phishing_catcher](https://github.com/x0rz/phishing_catcher) - Catching malicious phishing domain names
3. [bug-bounty-list.txt](https://gist.github.com/Plazmaz/c615559f0d71168c831583778afdb0b9) - A list of bug bounty urls


License
----
MIT
