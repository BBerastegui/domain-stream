import argparse
import logging
import os
import signal
import time
from queue import Queue
from threading import Lock
from threading import Thread

import socket
import netaddr
import tldextract
import yaml
from boto3.session import Session
from certstream.core import CertStreamClient
from requests.adapters import HTTPAdapter
from termcolor import cprint

ARGS = argparse.Namespace()
CONFIG = yaml.safe_load(open("config.yaml"))
INPUT_DOMAINS = [line.strip() for line in open("input_domains.txt")]
KEYWORD_DOMAINS = []
QUEUE_SIZE = CONFIG['queue_size']
UPDATE_INTERVAL = CONFIG['update_interval']  # seconds
RATE_LIMIT_SLEEP = CONFIG['rate_limit_sleep']  # seconds

FOUND_COUNT = 0


class UpdateThread(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.checked_domains_since_last_update = 0

        super().__init__(*args, **kwargs)

    def run(self):
        while True:
            checked_domains = len(self.q.checked_domains)

            if checked_domains > 1:
                cprint("{0} domains checked ({1:.0f}b/s), {2} domains found".format(
                    checked_domains,
                    (checked_domains - self.checked_domains_since_last_update) / UPDATE_INTERVAL,
                    FOUND_COUNT), "cyan")

            self.checked_domains_since_last_update = checked_domains
            time.sleep(UPDATE_INTERVAL)


class CertStreamThread(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.c = CertStreamClient(
            self.process, skip_heartbeats=True, on_open=None, on_error=None)

        super().__init__(*args, **kwargs)

    def run(self):
        while True:
            cprint("Waiting for Certstream events - this could take a few minutes to queue up...",
               "yellow", attrs=["bold"])
            self.c.run_forever()
            time.sleep(10)

    def process(self, message, context):
        if message["message_type"] == "heartbeat":
            return

        if message["message_type"] == "certificate_update":
            all_domains = message["data"]["leaf_cert"]["all_domains"]

            if ARGS.skip_lets_encrypt and "Let's Encrypt" in message["data"]["chain"][0]["subject"]["aggregated"]:
                return

            for domain in set(all_domains):
                # All the domains being extracted
                # Just put the domain in the list so we can process it later
                self.q.put( domain )
                # any(keyword in ",".join(objects) for keyword in KEYWORDS)


class DomainQueue( Queue ):
    def __init__(self, maxsize):
        self.lock = Lock()
        self.checked_domains = list()
        self.rate_limited = False
        self.next_yield = 0

        super().__init__(maxsize)

    def put(self, domain):
        if domain not in self.checked_domains:
            self.checked_domains.append( domain )
            super().put( domain )

    def get(self):
        with self.lock:
            t = time.monotonic()
            if self.rate_limited and t < self.next_yield:
                time.sleep(self.next_yield - t)
                t = time.monotonic()
                self.rate_limited = False

            self.next_yield = t + RATE_LIMIT_SLEEP

        return super().get()


class DomainWorker( Thread ):
    def __init__(self, q, *args, **kwargs):
        self.q = q

        super().__init__(*args, **kwargs)

    def run(self):
        while True:
            try:
                domain = self.q.get()
                # print(domain)
                self.__process(domain)
            except Exception as e:
                print(e)
                pass
            finally:
                self.q.task_done()

    def __process(self, domain):
        if self.__domain_contains_any_keywords(domain):
            # Remove wildcard domains
            domain = domain[2:] if domain.startswith('*.') else domain
            if ARGS.resolve:
                # Resolve domain
                self.__check_resolution(domain)
                pass
            else:
                cprint( "Found domain '{}'".format( domain ), "green", attrs=["bold"] )
                self.__log( domain )


    def __check_resolution(self, domain):
        try:
            # Resolve
            ip = netaddr.IPAddress( socket.gethostbyname( domain ) )
            ip = str(ip)
            cprint( "Found domain '{}', resolving with IP '{}'".format( domain, ip ), "green", attrs=["bold"] )
            if ARGS.only_resolving:
                self.__log( domain + "," + ip )
        except Exception as e:
            cprint( "Found domain '{}', not resolving to an IP.".format( domain), "green", attrs=["bold"] )
            if not ARGS.only_resolving:
                self.__log( domain )
            pass

    def __domain_contains_any_keywords(self, domain):
        try:
            return any(keyword in domain for keyword in KEYWORD_DOMAINS)
        except:
            return False

    def __log(self, new_domain):
        global FOUND_COUNT
        FOUND_COUNT += 1

        if ARGS.log_to_file:
            with open("domains.log", "a+") as log:
                log.write("%s%s" % (new_domain, os.linesep) )


def get_permutations(domain):
    perms = [
        "%s-" % domain,
        "-%s-" % domain,
        "-%s" % domain,
        #"%s." % domain,
        ".%s." % domain,
        ".%s" % domain,
        ".%s-" % domain,
        "-%s" % domain,
        "-%s." % domain,
        ".%s." % domain
    ]
    return perms


def main():
    parser = argparse.ArgumentParser(description="Find interesting domains by watching certificate transparency logs.",
                                     usage="python domain-stream.py",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--resolve", action="store_true", dest="resolve", default=False,
                        help="Resolve domains")
    parser.add_argument("--only-resolving", action="store_true", dest="only_resolving", default=False,
                        help="Only log domains resolving to IP addresses")
    parser.add_argument("--skip-lets-encrypt", action="store_true", dest="skip_lets_encrypt", default=False,
                        help="Skip certs (and thus listed domains) issued by Let's Encrypt CA")
    parser.add_argument("-t", "--threads", metavar="", type=int, dest="threads", default=20,
                        help="Number of threads to spawn. More threads = more power. Limited to 5 threads if unauthenticated.")
    parser.add_argument("-l", "--log", dest="log_to_file", default=False, action="store_true",
                        help="Log found domains to a file domains.log")
    parser.add_argument( "--keywords-only", dest="keywords_only", default=False, action="store_true",
                         help="Input based only on keywords. Permutations will be made with those." )

    parser.parse_args(namespace=ARGS)
    logging.disable(logging.WARNING)

    # Defaulting to 5 threads
    if not ARGS.threads:
        ARGS.threads = 5

    threads = list()

    global KEYWORD_DOMAINS

    if ARGS.keywords_only:
        for domain in INPUT_DOMAINS:
            KEYWORD_DOMAINS += get_permutations( domain )
    else:
        KEYWORD_DOMAINS = INPUT_DOMAINS

    try:
        q = DomainQueue( maxsize=QUEUE_SIZE )
        threads.extend( [DomainWorker( q ) for _ in range( 0, ARGS.threads )] )
        threads.extend([UpdateThread(q), CertStreamThread(q)])
        [t.start() for t in threads]

        signal.pause()  # pause the main thread
    except KeyboardInterrupt:
        cprint("Quitting - waiting for threads to finish up...",
               "yellow", attrs=["bold"])
        [t.join() for t in threads]


if __name__ == "__main__":
    main()
