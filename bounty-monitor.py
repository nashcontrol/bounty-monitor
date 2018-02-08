#!/usr/bin/env python
# Copyright (c) 2018 @nashcontrol

import os
import argparse
import logging
import sqlite3
import re
import time as t
import socket
import ssl
import threading

#python 2 and 3 compatibilities
try:
    from queue import Queue
except ImportError:
    from Queue import Queue

from datetime import datetime
import bs4
from termcolor import colored
from tld import get_tld
import requests
from requests.adapters import HTTPAdapter
import tqdm
import certstream


# Current execution list
QUEUE_SIZE = 100
INTERNAL_DOMAINS = list()
BOUNTY_LIST = [line.strip() for line in open('bug-bounty-list.txt')]
MONITOR_QUEUE = Queue(maxsize=QUEUE_SIZE)
PBAR = tqdm.tqdm(desc='certificate_update', unit='cert')

# Maintain list of found sub-domains in a database
DATABASE = 'subdomains.db'
CONNECTION = sqlite3.connect(DATABASE, check_same_thread=False)
DB_CURSOR = CONNECTION.cursor()
LOCK = threading.Lock()


class MonitorWorker(threading.Thread):
    def __init__(self, q, subdomain_age, log_filename="subdomains", verbose=False, *args, **kwargs):
        self.q = q
        self.subdomain_age = subdomain_age
        self.log_filename = log_filename
        self.verbose = verbose
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=2))

        super(MonitorWorker, self).__init__(*args, **kwargs)

    def run(self):
        while True:
            new_subdomain = self.q.get()
            self.log(new_subdomain, False)
            try:
                subdomain_age, connection_status = self.ssl_creation_datetime(new_subdomain)
                # Check if subdomain is new
                if (subdomain_age >= 0) and (subdomain_age < self.subdomain_age):              
                    # Check new subdomain is already live
                    check_response = self.session.get("https://" + new_subdomain, timeout=3)
                    page_title = bs4.BeautifulSoup(check_response.text, "html.parser").title
                    if (page_title is not None):
                        page_title = page_title.text.encode('utf8').strip()
                    tqdm.tqdm.write(
                        "[!] Subdomain found and it is alive: "
                        "{}, (Domain age: {} days), (Title={}), (response code={})".format(colored(new_subdomain, 'green', attrs=['underline', 'bold']), subdomain_age, page_title, check_response.status_code))
                    update_subdomain(new_subdomain, "Y")
                    # TODO: check S3 matching buckets
                    self.log(new_subdomain, True)
                elif self.verbose:
                    tqdm.tqdm.write(
                        "[!] Subdomain found: "
                        "{} Domain age: {} days (obtain certificate from server = {}) ".format(colored(new_subdomain, 'white', attrs=['underline']),subdomain_age,connection_status))

                self.log(new_subdomain, False)

            except Exception as e:
                logging.exception("Subdomain found but an error occured while processing: %s " % new_subdomain)
            finally:
                self.q.task_done()

    def log(self, new_subdomain, live):
        """Log file created with all subdomains found subdomains to all_subdomains.log and ones that are live to live_subdomains.log (default)"""

        if live:
            with open("live_%s.log" % self.log_filename, "a+") as log:
                log.write("%s%s" % (new_subdomain, os.linesep))
            return

        with open("all_%s.log" % self.log_filename, "a+") as log:
            log.write("%s%s" % (new_subdomain, os.linesep))

    def ssl_creation_datetime(self, hostname):
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        try:
            conn.connect((hostname, 443))
            ssl_info = conn.getpeercert()
            conn.shutdown(socket.SHUT_RDWR)
            # parse the string from the certificate into a Python datetime object
            return (datetime.now() - datetime.strptime(ssl_info['notBefore'], ssl_date_fmt)).days, "OK"
        except socket.error:
            return -1, "Unreachable"
        except ssl.SSLError:
            print(conn.getpeercert()['notBefore'])
            return -1, "Certificate Error"
        except ssl.CertificateError:
            return -1, "Certificate Error"
        finally:
            conn.close()



def check_subdomain_not_known_in_db(subdomain):
    DB_CURSOR.execute("select subdomain from subdomains where subdomain = ?", (subdomain, ))
    already_found = DB_CURSOR.fetchall()
    process_new_subdomain = True
    try:
        for known_subdomain in already_found:
            if known_subdomain[0] == subdomain:
                process_new_subdomain = False

    except Exception as e:
        # DB is probably empty
        process_new_subdomain = True
    return process_new_subdomain


def update_subdomain(subdomain, alive):
    """Subdomain database is maintained locally to keep track of identified live and known subdomains."""
    tld = get_tld(subdomain, as_object=True, fail_silently=True, fix_protocol=True)
    try:
        #synchronize multithread DB_CURSOR.execute
        LOCK.acquire(True)
        if alive == "N":
            DB_CURSOR.execute("insert into subdomains(subdomain, domain, first_found, alive, source) values(?, ?, ?, ?, ?)", (subdomain, tld.tld, datetime.now(), 0, "BountyMonitor"))
            CONNECTION.commit()
        elif alive == "Y":
            DB_CURSOR.execute("update subdomains set alive=1 where subdomain = ?", (subdomain, ))
            CONNECTION.commit()
    finally:
        LOCK.release()


def monitor(message, context):
    """certstream events callback handler"""

    all_domains = ""
    if message['message_type'] == "heartbeat":
        return

    if message["message_type"] == "certificate_update":
        all_domains = message["data"]["leaf_cert"]["all_domains"]
        
    for domain in set(all_domains):
        PBAR.update(1)

        # all magic happens here
        try:
            if domain.count(".") > 1 and not domain.startswith("*.") and not re.search("\d$", domain) and "cloudflaressl" not in domain and "xn--" not in domain and not domain.endswith("local"):
                tld = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
                if tld is not None and tld.tld in BOUNTY_LIST and tld.tld != domain and tld.subdomain != "www":
                    if check_subdomain_not_known_in_db(domain):
                        update_subdomain(domain, "N")
                        MONITOR_QUEUE.put(domain)
        except Exception as e:
            logging.exception("message")
            print (domain)

    t.sleep(.1)


def init_db():
    try:
        DB_CURSOR.execute("select subdomain from subdomains")

    except:
        # DB is empty
        tqdm.tqdm.write("[!] Database is empty, rebuilding known sub-domains from public sources (TODO)")

        DB_CURSOR.execute("CREATE TABLE `subdomains` ( `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE, `subdomain` TEXT UNIQUE, `domain` TEXT, `first_found` TEXT, `alive` INTEGER, `source` TEXT )")
        for domain in BOUNTY_LIST:
            get_subdomains_for_domain(domain)

        # TODO: get sub-domains from threatcrowd, censys, etc.


def get_subdomains_for_domain(domain):
    """populate known sub-domains in db"""


def main():
    logging.basicConfig(filename='bounty_errors.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(
        description="Leverage certificate transparency live feed to monitor for newly issued subdomain cerficates, for domains participating in bug bounty programs",
        usage="python bounty_monitor.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-l", "--log", dest="log_to_file", default="subdomains", action="store_true", help="Log found subdomains to all_subdomains.log and ones that are live to live_subdomains.log")
    parser.add_argument("--no_probe_s3_bucket", dest="probe_s3_bucket", default=True, action="store_true", help="Do not attempt to guess associated S3 buckets based on the new subdomain name")
    parser.add_argument("-t", "--threads", metavar="", type=int, dest="threads", default=10, help="Number of threads to spawn.")
    parser.add_argument("-d", "--days", metavar="", type=int, dest="subdomain_age", default=90, help="Number of days since current certificate registration.")
    parser.add_argument("-v", "--verbose", metavar="", type=int, dest="verbose", default=False, help="Increased verbosity, prints all identifed subdomains  matching the bugbounty list")

    args = parser.parse_args()
    logging.disable(logging.WARNING)

    init_db()

    for _ in range(1, args.threads):
        thread = MonitorWorker(MONITOR_QUEUE,args.subdomain_age,args.log_to_file,args.verbose)
        thread.setDaemon(True)
        thread.start()
    
    # TODO: check if previously found subdomain is alive every 30 minutes

    print ("Waiting for certstream events - this could take a few minutes to queue up...")
    certstream.listen_for_events(monitor)  # this is blocking, so I added some sleep..

    print ("Qutting - waiting for threads to finish up...")
    MONITOR_QUEUE.join()


if __name__ == "__main__":
    main()
