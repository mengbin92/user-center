#!/usr/bin/env python3
"""Builds the benchmark fixtures over the public API.

Logs in every benchmark account once (the login endpoint allows 30 attempts per
5 minutes per IP, so this pool cannot be rebuilt inside a scenario), ensures the
benchmark organization exists, and writes the session pool for k6.

Prints one JSON line on stdout: {"org_id": "...", "sessions": N}.
"""

import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request


def open_jar(base_url):
    jar = http.cookiejar.CookieJar()
    return jar, urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def cookie_value(jar, name):
    for cookie in jar:
        if cookie.name == name:
            return cookie.value
    return ""


def call(opener, method, url, csrf="", body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if csrf:
        request.add_header("X-CSRF-Token", csrf)
    try:
        with opener.open(request, timeout=15) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else {}
    except urllib.error.HTTPError as err:
        payload = err.read()
        try:
            parsed = json.loads(payload) if payload else {}
        except json.JSONDecodeError:
            parsed = {"raw": payload.decode("utf-8", "replace")}
        return err.code, parsed


def login(base_url, username, password):
    jar, opener = open_jar(base_url)
    opener.open(base_url + "/api/v1/auth/context", timeout=15).read()
    csrf = cookie_value(jar, "uc_csrf")
    if not csrf:
        raise SystemExit(f"no csrf cookie for {username}")
    status, body = call(opener, "POST", base_url + "/api/v1/auth/login", csrf,
                        {"username": username, "password": password})
    if status != 200:
        raise SystemExit(f"login {username} failed: {status} {body}")
    cookie = "; ".join(
        f"{cookie.name}={cookie.value}"
        for cookie in jar
        if cookie.name in ("uc_csrf", "uc_session")
    )
    if "uc_session=" not in cookie:
        raise SystemExit(f"login {username} returned no session cookie")
    return opener, csrf, cookie


def ensure_organization(base_url, opener, csrf, code):
    status, body = call(opener, "GET", base_url + "/api/v1/orgs")
    if status != 200:
        raise SystemExit(f"list organizations failed: {status} {body}")
    for item in body.get("items") or []:
        if item.get("code") == code:
            return item.get("id", "")
    status, body = call(opener, "POST", base_url + "/api/v1/orgs", csrf,
                        {"code": code, "name": "Bench Org"})
    if status != 200:
        raise SystemExit(f"create organization failed: {status} {body}")
    return body.get("id", "")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--prefix", default="bench")
    parser.add_argument("--accounts", type=int, default=24)
    parser.add_argument("--password", default="BenchPass-12345")
    parser.add_argument("--org-code", default="bench")
    parser.add_argument("--sessions-out", required=True)
    args = parser.parse_args()

    sessions = []
    owner_opener = None
    owner_csrf = ""
    for index in range(1, args.accounts + 1):
        username = f"{args.prefix}{index:02d}"
        opener, csrf, cookie = login(args.base_url, username, args.password)
        if owner_opener is None:
            owner_opener, owner_csrf = opener, csrf
        sessions.append({"username": username, "cookie": cookie})

    org_id = ensure_organization(args.base_url, owner_opener, owner_csrf, args.org_code)
    if not org_id:
        raise SystemExit("organization id is empty")

    with open(args.sessions_out, "w", encoding="utf-8") as handle:
        json.dump(sessions, handle)

    print(json.dumps({"org_id": org_id, "sessions": len(sessions)}))


if __name__ == "__main__":
    sys.exit(main())
