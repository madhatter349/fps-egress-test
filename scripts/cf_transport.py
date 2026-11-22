#!/usr/bin/env python3
"""TLS-matched transport for the Cloudflare managed-challenge flow.

Every request in the flow (challenge GET, challenge POSTs, clearance GET) goes
through one curl_cffi Session with a single Chrome impersonation profile, so the
TLS/JA3+JA4, HTTP/2 settings, header order and UA/client-hints all agree with
each other and with the UA the jsdom VM reports in the payload.

Subcommands (all print one JSON object on stdout):

  challenge <url> <state.json>
      GET the challenge page, persist cookies + html + ray + UA to state.json.

  submit <state.json> <posts.json> [--out result.json]
      POST each VM-produced payload in order over the same session, persist the
      updated cookie jar, report per-post status and any cf_clearance minted.

  fetch <state.json> <url>
      GET url with the session's cookies; report status/headers/body.

Exit codes: 0 ok, 2 usage/IO, 3 transport error.
"""
import json
import os
import sys
import time
from urllib.parse import urljoin, urlparse

from curl_cffi import requests

# One profile for the whole flow. "chrome" in curl_cffi 0.17 == Chrome 152 on
# Windows with coherent sec-ch-ua client hints. Do not mix profiles: a UA that
# disagrees with the TLS profile is punished harder than plain curl (measured in
# fps-access/docs/cf-clearance-transfer-test.md section 2.1).
IMPERSONATE = "chrome"

# curl_cffi 0.17 resolves "chrome" -> chrome152 and sets the UA inside libcurl,
# so it is not readable from Session.headers. This is the exact string that
# profile sends (verified against an echo endpoint: Chrome/152.0.0.0, Windows
# NT 10.0; Win64; x64, sec-ch-ua-platform "Windows"). The VM must report the
# same UA or the payload contradicts the TLS fingerprint.
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36")

# The site's WAF challenges requests whose UA advertises Chrome < 155 even when
# a valid cf_clearance is presented (measured: 151/152/153 -> 403, 155..160 ->
# 200 with the same cookie pair). curl_cffi's newest TLS profile is chrome152,
# so the UA header is overridden to 157 while the TLS/JA4 stays chrome152.
CHROME_MAJOR = "157"
SEC_CH_UA = f'"Chromium";v="{CHROME_MAJOR}", "Not?A_Brand";v="24", "Google Chrome";v="{CHROME_MAJOR}"'
UA_HEADERS = {"User-Agent": CHROME_UA, "sec-ch-ua": SEC_CH_UA}

# Headers curl_cffi/impersonation owns. Replaying these from a captured VM
# request would either be ignored or desynchronise the fingerprint.
OWNED_HEADERS = {
    "host", "user-agent", "accept-encoding", "content-length", "connection",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site",
    "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "upgrade-insecure-requests",
}


def die(msg, code=3):
    print(json.dumps({"ok": False, "error": msg}), file=sys.stdout)
    sys.exit(code)


def origin_of(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def new_session(state=None):
    proxy = os.environ.get("CF_PROXY") or None
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session(impersonate=IMPERSONATE, proxies=proxies)
    s.headers.update(UA_HEADERS)
    if state:
        for c in state.get("cookies", []):
            try:
                s.cookies.set(c["name"], c["value"], domain=c.get("domain") or None,
                              path=c.get("path") or "/")
            except Exception:
                s.cookies.set(c["name"], c["value"])
    return s


def dump_cookies(s):
    out = []
    for c in s.cookies.jar:
        out.append({"name": c.name, "value": c.value,
                    "domain": c.domain, "path": c.path})
    return out


def save_state(path, state, s):
    state["cookies"] = dump_cookies(s)
    state["saved_at"] = time.time()
    with open(path, "w") as f:
        json.dump(state, f)


def ua_of(s):
    return CHROME_UA


def cmd_challenge(url, state_path):
    s = new_session()
    try:
        r = s.get(url, allow_redirects=False, timeout=45)
    except Exception as e:
        die(f"challenge GET failed: {e}")
    body = r.content
    state = {
        "url": url,
        "impersonate": IMPERSONATE,
        "ua": ua_of(s),
        "status": r.status_code,
        "ray": r.headers.get("cf-ray"),
        "cf_mitigated": r.headers.get("cf-mitigated"),
        "html_len": len(body),
        "html_path": state_path + ".html",
    }
    with open(state["html_path"], "wb") as f:
        f.write(body)

    # The challenge VM lives at /cdn-cgi/challenge-platform/.../orchestrate/
    # chl_page/v1?ray=<ray>. Fetch it over the same session so the script bytes
    # and the challenge instance belong to one client.
    import re
    m = re.search(rb"challenge-platform/[^\"'\\s)]*orchestrate/chl_page/v1\?ray=[0-9a-f]+", body)
    if m:
        surl = origin_of(url) + "/cdn-cgi/" + m.group(0).decode()
        try:
            sr = s.get(surl, timeout=45, headers={
                "Referer": url, "Accept": "*/*",
                "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Dest": "script",
            })
            state["script_url"] = surl
            state["script_status"] = sr.status_code
            state["script_len"] = len(sr.content)
            state["script_path"] = state_path + ".js"
            with open(state["script_path"], "wb") as f:
                f.write(sr.content)
        except Exception as e:
            state["script_error"] = str(e)
    save_state(state_path, state, s)
    print(json.dumps({"ok": True, **{k: v for k, v in state.items() if k != "cookies"},
                      "cookies": [c["name"] for c in state["cookies"]]}))


def cmd_submit(state_path, posts_path, out_path=None):
    state = json.load(open(state_path))
    posts = json.load(open(posts_path))
    if isinstance(posts, dict):
        posts = posts.get("posts", [])
    s = new_session(state)
    origin = "{0.scheme}://{0.netloc}".format(urlparse(state["url"]))
    results = []
    for i, p in enumerate(posts):
        purl = p.get("url") or ""
        if purl.startswith("/"):
            purl = origin + purl
        elif not purl.startswith("http"):
            purl = urljoin(state["url"], purl)
        headers = {k: v for k, v in (p.get("headers") or {}).items()
                   if k.lower() not in OWNED_HEADERS}
        headers.setdefault("Origin", origin)
        headers.setdefault("Referer", state["url"])
        headers.setdefault("Sec-Fetch-Site", "same-origin")
        headers.setdefault("Sec-Fetch-Mode", "cors")
        headers.setdefault("Sec-Fetch-Dest", "empty")
        body = p.get("body") or ""
        t0 = time.time()
        try:
            r = s.post(purl, data=body.encode("utf-8") if isinstance(body, str) else body,
                       headers=headers, allow_redirects=False, timeout=45)
        except Exception as e:
            results.append({"i": i, "url": purl, "error": str(e)})
            continue
        results.append({
            "i": i,
            "url": purl,
            "status": r.status_code,
            "ms": round((time.time() - t0) * 1000),
            "resp_headers": {k.lower(): v for k, v in r.headers.items()},
            "body_len": len(r.content),
            "body_prefix": r.text[:400],
        })
    save_state(state_path, state, s)
    clearance = next((c["value"] for c in state["cookies"] if c["name"] == "cf_clearance"), None)
    out = {"ok": True, "posts": results, "cf_clearance": clearance,
           "cf_clearance_len": len(clearance) if clearance else 0,
           "cookies": [c["name"] for c in state["cookies"]]}
    if out_path:
        with open(out_path, "w") as f:
            json.dump(out, f, indent=2)
    print(json.dumps(out))


def cmd_post1(state_path, url, body_path, headers_json):
    """One-shot POST used by the live VM bridge: same session, one request."""
    state = json.load(open(state_path))
    s = new_session(state)
    origin = origin_of(state["url"])
    if url.startswith("/"):
        url = origin + url
    headers = {k: v for k, v in json.loads(headers_json or "{}").items()
               if k.lower() not in OWNED_HEADERS}
    headers.setdefault("Origin", origin)
    headers.setdefault("Referer", state["url"])
    headers.setdefault("Sec-Fetch-Site", "same-origin")
    headers.setdefault("Sec-Fetch-Mode", "cors")
    headers.setdefault("Sec-Fetch-Dest", "empty")
    body = open(body_path, "rb").read() if body_path != "-" else b""
    try:
        r = s.post(url, data=body, headers=headers, allow_redirects=False, timeout=45)
    except Exception as e:
        die(f"post1 failed: {e}")
    save_state(state_path, state, s)
    import base64
    print(json.dumps({
        "ok": True, "status": r.status_code,
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body_b64": base64.b64encode(r.content).decode(),
        "cf_clearance": next((c["value"] for c in state["cookies"] if c["name"] == "cf_clearance"), None),
    }))


def cmd_fetch(state_path, url):
    state = json.load(open(state_path))
    s = new_session(state)
    try:
        r = s.get(url, allow_redirects=False, timeout=45)
    except Exception as e:
        die(f"fetch failed: {e}")
    save_state(state_path, state, s)
    print(json.dumps({
        "ok": True,
        "status": r.status_code,
        "headers": {k.lower(): v for k, v in r.headers.items()},
        "body": r.text,
        "body_len": len(r.content),
    }))


def cmd_serve(state_path):
    """Persistent JSON-lines bridge: one Session, one connection pool, for the
    whole challenge flow. Reads {"cmd":...} lines on stdin, writes one JSON line
    per request on stdout."""
    import base64
    state = json.load(open(state_path)) if os.path.exists(state_path) else {"url": None}
    s = new_session(state)
    origin = origin_of(state["url"]) if state.get("url") else None
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            print(json.dumps({"ok": False, "error": f"bad json: {e}"}), flush=True)
            continue
        cmd = req.get("cmd")
        try:
            if cmd == "challenge":
                url = req["url"]
                if req.get("fresh"):
                    # Drop the jar so Cloudflare issues a challenge instead of
                    # serving the page to a warm __cf_bm.
                    s.cookies.clear()
                    state["cookies"] = []
                state["url"] = url
                origin = origin_of(url)
                r = s.get(url, allow_redirects=False, timeout=45)
                body = r.content
                state.update({"status": r.status_code, "ray": r.headers.get("cf-ray"),
                              "cf_mitigated": r.headers.get("cf-mitigated"),
                              "html_len": len(body), "ua": CHROME_UA,
                              "impersonate": IMPERSONATE})
                state["html_path"] = state_path + ".html"
                with open(state["html_path"], "wb") as f:
                    f.write(body)
                import re
                m = re.search(rb"challenge-platform/[^\"'\s)]*orchestrate/chl_page/v1\?ray=[0-9a-f]+", body)
                if m:
                    surl = origin + "/cdn-cgi/" + m.group(0).decode()
                    sr = s.get(surl, timeout=45, headers={
                        "Referer": url, "Accept": "*/*", "Sec-Fetch-Site": "same-origin",
                        "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script"})
                    state["script_url"] = surl
                    state["script_status"] = sr.status_code
                    state["script_len"] = len(sr.content)
                    state["script_path"] = state_path + ".js"
                    with open(state["script_path"], "wb") as f:
                        f.write(sr.content)
                save_state(state_path, state, s)
                print(json.dumps({"ok": True, "status": r.status_code, "ray": state["ray"],
                                  "cf_mitigated": state["cf_mitigated"],
                                  "html_path": state["html_path"],
                                  "script_path": state.get("script_path"),
                                  "script_status": state.get("script_status"),
                                  "ua": CHROME_UA,
                                  "cookies": [c["name"] for c in state["cookies"]]}), flush=True)
            elif cmd in ("post", "get"):
                url = req["url"]
                if url.startswith("/"):
                    url = origin + url
                headers = {k: v for k, v in (req.get("headers") or {}).items()
                           if k.lower() not in OWNED_HEADERS}
                if cmd == "post":
                    headers.setdefault("Origin", origin)
                    headers.setdefault("Referer", state["url"])
                    headers.setdefault("Sec-Fetch-Site", "same-origin")
                    headers.setdefault("Sec-Fetch-Mode", "cors")
                    headers.setdefault("Sec-Fetch-Dest", "empty")
                    body = base64.b64decode(req.get("body_b64") or "")
                    r = s.post(url, data=body, headers=headers, allow_redirects=False, timeout=45)
                else:
                    r = s.get(url, headers=headers, allow_redirects=False, timeout=45)
                save_state(state_path, state, s)
                clearance = next((c["value"] for c in state["cookies"] if c["name"] == "cf_clearance"), None)
                print(json.dumps({"ok": True, "status": r.status_code,
                                  "headers": {k.lower(): v for k, v in r.headers.items()},
                                  "body_b64": base64.b64encode(r.content).decode(),
                                  "cf_clearance": clearance,
                                  "cookies": [c["name"] for c in state["cookies"]]}), flush=True)
            elif cmd == "quit":
                print(json.dumps({"ok": True}), flush=True)
                return
            else:
                print(json.dumps({"ok": False, "error": f"unknown cmd {cmd}"}), flush=True)
        except Exception as e:
            print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}), flush=True)


def main(argv):
    if len(argv) < 2:
        die("usage: cf_transport.py challenge|submit|fetch ...", 2)
    cmd = argv[1]
    if cmd == "challenge" and len(argv) >= 4:
        cmd_challenge(argv[2], argv[3])
    elif cmd == "submit" and len(argv) >= 4:
        out = argv[5] if len(argv) >= 6 and argv[4] == "--out" else None
        cmd_submit(argv[2], argv[3], out)
    elif cmd == "serve" and len(argv) >= 3:
        cmd_serve(argv[2])
    elif cmd == "post1" and len(argv) >= 6:
        cmd_post1(argv[2], argv[3], argv[4], argv[5])
    elif cmd == "fetch" and len(argv) >= 4:
        cmd_fetch(argv[2], argv[3])
    else:
        die(f"bad arguments for {cmd}", 2)


if __name__ == "__main__":
    main(sys.argv)
