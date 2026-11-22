#!/usr/bin/env python3
"""Look up ASN/org for an IP via ip-api.com. Prints ASxxxx|asname|country|isp."""
import json
import sys
import urllib.request

ip = sys.argv[1]
url = f"http://ip-api.com/json/{ip}?fields=status,as,asname,isp,country"
try:
    with urllib.request.urlopen(url, timeout=15) as r:
        d = json.load(r)
    if d.get("status") != "success":
        print("LOOKUP_FAIL|-|-|-")
    else:
        print(f'{d.get("as","?")}|{d.get("asname","?")}|{d.get("country","?")}|{d.get("isp","?")}')
except Exception as e:
    print(f"LOOKUP_ERR({type(e).__name__})|-|-|-")
