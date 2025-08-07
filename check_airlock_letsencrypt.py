#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nagios/Thruk Plugin: Check Let's Encrypt certificate expiry for Airlock Gateway
Author: Bela Richartz
Description: Checks expiry of all ACME-managed (Let's Encrypt) certificates via Airlock REST API.
Usage: Place this script in your Nagios/Thruk plugins directory and configure with required arguments.
"""

import sys
import argparse
import requests
from requests.adapters import Retry
from requests.sessions import HTTPAdapter
import urllib3
from urllib.parse import urlencode
import ssl
import socket
from datetime import datetime, timezone

PLUGIN_NAME = "check_airlock_letsencrypt"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "Bela Richartz"
PLUGIN_LICENSE = "MIT"

Nagios_States = {
    "OK": 0,
    "WARNING": 1,
    "CRITICAL": 2,
    "UNKNOWN": 3
}


def build_url(base_url, *res, **params):
    u = base_url
    for r in res:
        u = '{}/{}'.format(u, r)
    if params:
        u = '{}?{}'.format(u, urlencode(params))
    return u

def get_cert_expiry_date(hostname):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            subject_issuer = dict(x[0] for x in cert['issuer'])
            if "Let's Encrypt" not in subject_issuer.get('organizationName', ''):
                return None, "Not Let's Encrypt"
            expiry = cert['notAfter']
            expires = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return expires, None

class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop('timeout', 10)  # Default timeout is 10 seconds
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        if 'timeout' in kwargs: del kwargs['timeout']
        return super().send(request, timeout=self.timeout, **kwargs)

def main():
    parser = argparse.ArgumentParser(
        description="Nagios/Thruk Plugin: Check Airlock ACME/Let's Encrypt certificate expiry",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--airlock-host', required=True, help='Airlock Gateway hostname (FQDN or IP)')
    parser.add_argument('--api-token', required=True, help='Bearer API Token')
    parser.add_argument('-w', '--warning', type=int, default=30, help='Warning threshold (days)')
    parser.add_argument('-c', '--critical', type=int, default=15, help='Critical threshold (days)')
    parser.add_argument('-t', '--timeout', type=int, default=50, help='Plugin timeout (seconds)')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {PLUGIN_VERSION}')

    args = parser.parse_args()
    BASE_URL = f"https://{args.airlock_host}/airlock/rest"
    HEADERS = {
        'Authorization': f'Bearer {args.api_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    urllib3.disable_warnings()
    session = requests.sessions.session()
    adapter = TimeoutHTTPAdapter(max_retries=Retry(total=0, backoff_factor=0.1), timeout=args.timeout)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.verify = False
    session.headers.update(HEADERS)

    try:
        # 1. Create Session
        url = build_url(BASE_URL, 'session/create')
        r = session.post(url)
        r.raise_for_status()

        # 2. Load Active Configuration
        url = build_url(BASE_URL, 'configuration/configurations/load-active')
        r = session.post(url)
        r.raise_for_status()

        # 3. Fetch ALL Virtual Hosts
        url = build_url(BASE_URL, 'configuration/virtual-hosts')
        r = session.get(url)
        r.raise_for_status()
        vhosts = r.json()['data']

        # 4. Collect all ACME-managed FQDNs (certificateMode == 'ACME_SERVICE')
        acme_domains = set()
        for vhost in vhosts:
            attrs = vhost.get('attributes', {})
            tls = attrs.get('tls', {})
            if tls.get('certificateMode') == 'ACME_SERVICE':
                # Add main hostname
                if attrs.get('hostName'):
                    acme_domains.add(attrs['hostName'])
                # Add all alias names
                for alias in attrs.get('aliasNames', []):
                    acme_domains.add(alias)
        if not acme_domains:
            print("WARNING - No ACME-managed (Let's Encrypt) domains found in Airlock configuration.")
            sys.exit(Nagios_States["WARNING"])

        # 5. Check expiry per domain
        errors, ok, warn, crit = [], [], [], []
        min_days = None
        for domain in sorted(acme_domains):
            try:
                expiry, error = get_cert_expiry_date(domain)
                if error:
                    errors.append(f"{domain}({error})")
                    continue
                days_left = (expiry - datetime.now(timezone.utc)).days
                min_days = days_left if min_days is None else min(days_left, min_days)
                if days_left < args.critical:
                    crit.append(f"{domain}({days_left}d)")
                elif days_left < args.warning:
                    warn.append(f"{domain}({days_left}d)")
                else:
                    ok.append(f"{domain}({days_left}d)")
            except Exception as e:
                errors.append(f"{domain}(ERR:{e})")

        # 6. Print status and exit
        perf_output = f" | min_days={min_days};;;;"
        worst_state = 0
        output = []
        if crit:
            worst_state = Nagios_States["CRITICAL"]
            output.append(f"CRITICAL: {', '.join(crit)}")
        if warn:
            worst_state = max(worst_state, Nagios_States["WARNING"])
            output.append(f"WARNING: {', '.join(warn)}")
        if ok:
            worst_state = max(worst_state, Nagios_States['OK'])
            output.append(f"OK: {', '.join(ok)}")
        else:
            print(f"WARNING - No certs checked. Failures: {', '.join(errors)}")
            sys.exit(Nagios_States["WARNING"])

        if worst_state == Nagios_States["OK"]:
            print(f"OK - All ACME certs valid - {', '.join(ok)}")
        else:
            print(f"{list(Nagios_States)[worst_state]} - {' - '.join(output)} {perf_output}")
        sys.exit(worst_state)
    except Exception as e:
        print(f"WARNING - REST API or check failed: {e}")
        sys.exit(Nagios_States["WARNING"])
    finally:
        try:
            url = build_url(BASE_URL, 'session/terminate')
            r = session.post(url)
        except Exception:
            pass

if __name__ == "__main__":
    main()
