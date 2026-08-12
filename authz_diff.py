#!/usr/bin/env python3
"""
authz-diff — Access-control / IDOR tester by response differencing.

Take one captured request (the object owner's), replay it under other
identities — a different user's token, a stripped/unauthenticated request —
and diff the responses. If another user (or nobody) gets back the same data the
owner does, that's an IDOR / broken-object-level-authorization / auth-bypass.

This finds the bug class payload scanners miss: the server returns 200 and the
"right" shape, it just serves it to the wrong caller. The tool proves it by
comparing what each identity actually receives.

Zero third-party dependencies. Standard library only.

Usage:
  # baseline auth comes from the captured request; test another user + unauth
  authz-diff -r owner_request.txt \\
      --identity userB='Authorization: Bearer eyB...'

  # URL mode
  authz-diff -u https://api.site.com/v2/orders/1042 \\
      --header 'Authorization: Bearer OWNER' \\
      --identity userB='Authorization: Bearer OTHER' \\
      --identity staff='Cookie: session=abc'

  # multiple object ids at once (swap the id in the path/body)
  authz-diff -r owner_request.txt --identity userB='Authorization: Bearer B' \\
      --swap 1042=1043,1044

Scope note: only replay requests against targets you are authorized to test.
Registering/replaying a request is your assertion it is in scope (Rule Zero).
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

__version__ = "1.0.0"

# headers considered "identity-bearing" — replaced/removed per identity
AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")
SIMILAR_HIGH = 0.95   # >= => effectively the same response body
SIMILAR_MED = 0.60    # >= => materially similar
BODY_CAP = 200_000    # cap body size used for similarity (perf)


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[bytes] = None


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    error: Optional[str] = None

    @property
    def length(self) -> int:
        return len(self.body)

    @property
    def sha(self) -> str:
        return hashlib.sha256(self.body).hexdigest()[:12]


@dataclass
class Identity:
    name: str
    set_headers: dict[str, str] = field(default_factory=dict)  # header -> value
    strip_auth: bool = False


# ── parsing ─────────────────────────────────────────────────────────────────

def parse_raw_request(text: str, scheme: str) -> Request:
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        sys.exit("[!] empty request file")
    parts = lines[0].split()
    if len(parts) < 2:
        sys.exit(f"[!] bad request line: {lines[0]!r}")
    method, path = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body_text = "\n".join(lines[i + 1:]) if i + 1 <= len(lines) else ""
    body = body_text.encode() if body_text.strip() else None
    host = headers.get("Host") or headers.get("host")
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        if not host:
            sys.exit("[!] no Host header and path is not absolute — can't build URL")
        url = f"{scheme}://{host}{path}"
    return Request(method=method, url=url, headers=headers, body=body)


def parse_identity(spec: str) -> Identity:
    """spec = 'NAME=Header: value'  (empty value part => strip auth headers)."""
    if "=" not in spec:
        sys.exit(f"[!] bad --identity {spec!r} — use NAME='Header: value' or NAME=")
    name, rest = spec.split("=", 1)
    name = name.strip()
    rest = rest.strip()
    if not rest:
        return Identity(name=name, strip_auth=True)
    if ":" not in rest:
        sys.exit(f"[!] bad header in --identity {spec!r} — expected 'Header: value'")
    hk, hv = rest.split(":", 1)
    return Identity(name=name, set_headers={hk.strip(): hv.strip()})


def apply_identity(base: Request, ident: Identity) -> Request:
    headers = dict(base.headers)
    if ident.strip_auth:
        for k in list(headers):
            if k.lower() in AUTH_HEADERS:
                del headers[k]
    for k, v in ident.set_headers.items():
        # replace any existing header of the same name (case-insensitive)
        for existing in list(headers):
            if existing.lower() == k.lower():
                del headers[existing]
        headers[k] = v
    return Request(method=base.method, url=base.url, headers=headers, body=base.body)


def swap_ids(req: Request, swaps: list[tuple[str, str]]) -> Request:
    """Swap an object id in the request's PATH, QUERY and BODY only.

    The scheme/host/port (authority) is never rewritten: a naive global
    ``url.replace`` would let an id that also appears in the hostname
    (``api10.site.com`` with ``--swap 10=20``) redirect the request to a
    different, possibly out-of-scope host. We split the URL and only touch the
    path and query.
    """
    parts = urlsplit(req.url)
    path, query = parts.path, parts.query
    body = req.body.decode(errors="replace") if req.body else None
    for old, new in swaps:
        if old and old in parts.netloc:
            print(f"[!] swap '{old}'->'{new}' also matches the host "
                  f"'{parts.netloc}' — host left UNTOUCHED (path/query/body only)",
                  file=sys.stderr)
        path = path.replace(old, new)
        query = query.replace(old, new)
        if body is not None:
            body = body.replace(old, new)
    url = urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
    return Request(method=req.method, url=url, headers=dict(req.headers),
                   body=body.encode() if body is not None else None)


# ── sending ─────────────────────────────────────────────────────────────────

def send(req: Request, timeout: int, verify: bool) -> Response:
    r = urllib.request.Request(req.url, method=req.method, data=req.body)
    for k, v in req.headers.items():
        if k.lower() == "host":
            continue  # urllib sets Host from the URL
        if k.lower() == "content-length":
            continue
        r.add_header(k, v)
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            body = resp.read(BODY_CAP + 1)
            return Response(status=resp.status,
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            body=body)
    except urllib.error.HTTPError as e:
        body = e.read(BODY_CAP + 1)
        return Response(status=e.code,
                        headers={k.lower(): v for k, v in (e.headers or {}).items()},
                        body=body)
    except Exception as e:
        return Response(status=0, headers={}, body=b"", error=str(e))


# ── scoring ─────────────────────────────────────────────────────────────────

_SECRET_QS_KEYS = {"api_key", "apikey", "key", "token", "access_token", "auth",
                   "secret", "password", "passwd", "sig", "signature",
                   "session", "sid"}


def _redact_url(url: str) -> str:
    """Redact credential-ish query params so a written report / -o file never
    persists a secret embedded in the URL (auth *headers* are already not
    stored). Only the persisted/echoed URL is redacted — the live request still
    uses the real value."""
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    if not p.query:
        return url
    pairs = parse_qsl(p.query, keep_blank_values=True)
    red = [(k, "REDACTED" if k.lower() in _SECRET_QS_KEYS else v) for k, v in pairs]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(red), p.fragment))


def similarity(a: bytes, b: bytes) -> float:
    if not a and not b:
        return 1.0
    sa = a[:BODY_CAP].decode(errors="replace")
    sb = b[:BODY_CAP].decode(errors="replace")
    return difflib.SequenceMatcher(None, sa, sb).ratio()


def classify(baseline: Response, test: Response, ident: Identity,
             swapped: bool = False) -> dict:
    """Return a verdict dict for one identity vs the baseline (owner).

    ``swapped`` is True when the tested request points at a *different* object
    id than the owner baseline. In that case body-similarity to the owner's
    original object is NOT a valid "same data" signal (two different objects
    share only structural shape), so the verdict is driven by status alone:
    any 2xx for an object id this identity was not given is a BOLA candidate to
    confirm by hand.
    """
    if test.error:
        return {"severity": "ERROR", "reason": f"request failed: {test.error}"}
    if baseline.status < 200 or baseline.status >= 300:
        return {"severity": "INFO",
                "reason": f"baseline status {baseline.status} is not 2xx — "
                          "can't judge access control from it"}

    sim = similarity(baseline.body, test.body)
    len_delta = abs(baseline.length - test.length)
    protected = test.status in (401, 403) or (test.status == 404 and baseline.status == 200)

    if protected:
        why = f"identity '{ident.name}' correctly denied ({test.status})"
        if swapped and test.status == 404:
            why = (f"'{ident.name}' got 404 for the swapped object — denied OR the "
                   "object id does not exist (inconclusive)")
        return {"severity": "OK", "test_status": test.status, "reason": why}

    if swapped:
        # cross-object: similarity to the owner's original object is noise.
        if 200 <= test.status < 300:
            return {"severity": "MEDIUM", "test_status": test.status,
                    "len_delta": len_delta,
                    "reason": f"BOLA candidate: '{ident.name}' received 2xx for a "
                              "swapped object id it was not given — confirm the "
                              "returned object is not this identity's own data"}
        return {"severity": "INFO", "test_status": test.status,
                "reason": f"'{ident.name}' got status {test.status} for the swapped object"}

    # test got through (2xx / 3xx / other non-deny)
    is_unauth = ident.strip_auth
    if 200 <= test.status < 300 and sim >= SIMILAR_HIGH:
        sev = "CRITICAL" if is_unauth else "HIGH"
        kind = "UNAUTH ACCESS (missing authentication)" if is_unauth \
            else "IDOR / BOLA (cross-identity data access)"
        return {"severity": sev, "similarity": round(sim, 3),
                "test_status": test.status, "len_delta": len_delta,
                "reason": f"{kind}: '{ident.name}' received a response "
                          f"{round(sim*100)}% identical to the owner's"}
    if 200 <= test.status < 300 and sim >= SIMILAR_MED:
        return {"severity": "MEDIUM", "similarity": round(sim, 3),
                "test_status": test.status, "len_delta": len_delta,
                "reason": f"'{ident.name}' got 2xx with {round(sim*100)}% similar body "
                          "— accessible; verify whether it's the owner's data or its own"}
    if 200 <= test.status < 300:
        return {"severity": "LOW", "similarity": round(sim, 3),
                "test_status": test.status, "len_delta": len_delta,
                "reason": f"'{ident.name}' got 2xx but a different body "
                          f"({round(sim*100)}% similar) — likely its own/empty data"}
    return {"severity": "INFO", "similarity": round(sim, 3),
            "test_status": test.status,
            "reason": f"'{ident.name}' got status {test.status}"}


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
             "OK": 4, "INFO": 5, "ERROR": 6}


# ── run ─────────────────────────────────────────────────────────────────────

def run(base_req: Request, identities: list[Identity], swaps: list[tuple[str, str]],
        timeout: int, verify: bool) -> dict:
    results = {"url": _redact_url(base_req.url), "method": base_req.method,
               "findings": []}

    print(f"[*] baseline (owner) -> {base_req.method} {base_req.url}", file=sys.stderr)
    baseline = send(base_req, timeout, verify)
    results["baseline"] = {"status": baseline.status, "length": baseline.length,
                           "sha": baseline.sha, "error": baseline.error}
    print(f"    owner: status={baseline.status} len={baseline.length} sha={baseline.sha}",
          file=sys.stderr)

    targets = swaps or [None]
    for swap in targets:
        req_for_swap = swap_ids(base_req, [swap]) if swap else base_req
        swap_label = f" [id {swap[0]}->{swap[1]}]" if swap else ""
        # re-baseline against the swapped object as the owner? No — owner baseline is
        # the original object. For swapped ids we compare each identity's fetch of the
        # swapped object against the OWNER's original response.
        for ident in identities:
            test_req = apply_identity(req_for_swap, ident)
            print(f"[*] as '{ident.name}'{swap_label} ...", file=sys.stderr)
            test = send(test_req, timeout, verify)
            verdict = classify(baseline, test, ident, swapped=bool(swap))
            verdict["identity"] = ident.name
            if swap:
                verdict["swap"] = f"{swap[0]}->{swap[1]}"
            verdict["url"] = _redact_url(test_req.url)
            results["findings"].append(verdict)

    results["findings"].sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    return results


def print_report(results: dict) -> None:
    print("\n" + "=" * 60)
    print(f"authz-diff :: {results['method']} {results['url']}")
    b = results["baseline"]
    print(f"owner baseline: status={b['status']} len={b['length']} sha={b['sha']}")
    print("=" * 60)
    tag = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED ]",
           "LOW": "[low ]", "OK": "[ ok ]", "INFO": "[info]", "ERROR": "[err ]"}
    for f in results["findings"]:
        line = f"{tag.get(f['severity'], '[????]')} {f['reason']}"
        if f.get("swap"):
            line += f"  (obj {f['swap']})"
        print(line)
    sev = [f["severity"] for f in results["findings"]]
    hot = sum(1 for s in sev if s in ("CRITICAL", "HIGH"))
    verify = sum(1 for s in sev if s == "MEDIUM")
    bits = []
    if hot:
        bits.append(f"{hot} high-confidence finding(s) needing a PoC writeup")
    if verify:
        bits.append(f"{verify} to verify by hand (MEDIUM)")
    tail = "; ".join(bits) if bits else "no cross-identity access detected"
    print("-" * 60)
    print(f"{len(sev)} result(s) — {tail}")


def parse_swaps(spec: Optional[str]) -> list[tuple[str, str]]:
    if not spec:
        return []
    # format: OLD=NEW1,NEW2  -> [(OLD,NEW1),(OLD,NEW2)]
    if "=" not in spec:
        sys.exit(f"[!] bad --swap {spec!r} — use OLD=NEW1,NEW2")
    old, news = spec.split("=", 1)
    return [(old.strip(), n.strip()) for n in news.split(",") if n.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="authz-diff",
                                description="Access-control / IDOR tester by response diff")
    p.add_argument("-v", "--version", action="version", version=f"authz-diff {__version__}")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-r", "--request", help="raw HTTP request file (Burp-style)")
    src.add_argument("-u", "--url", help="target URL (URL mode)")
    p.add_argument("-X", "--method", default="GET", help="method for URL mode (default GET)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="header for URL mode, e.g. -H 'Authorization: Bearer OWNER' (repeatable)")
    p.add_argument("-d", "--data", help="request body for URL mode")
    p.add_argument("--identity", action="append", default=[], required=True,
                   help="test identity: NAME='Header: value', or NAME= to strip auth (repeatable)")
    p.add_argument("--no-unauth", action="store_true",
                   help="do not auto-add an unauthenticated identity")
    p.add_argument("--swap", help="swap object ids: OLD=NEW1,NEW2 (in URL + body)")
    p.add_argument("--scheme", default="https", choices=["https", "http"],
                   help="scheme when building URL from a raw request (default https)")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--no-verify", action="store_true", help="disable TLS verification")
    p.add_argument("-o", "--output", help="write JSON results to file")
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)

    if args.request:
        try:
            text = open(args.request, encoding="utf-8", errors="replace").read()
        except OSError as e:
            sys.exit(f"[!] cannot read request file: {e}")
        base_req = parse_raw_request(text, args.scheme)
    else:
        headers: dict[str, str] = {}
        for h in args.header:
            if ":" not in h:
                sys.exit(f"[!] bad -H {h!r}")
            k, val = h.split(":", 1)
            headers[k.strip()] = val.strip()
        base_req = Request(method=args.method.upper(), url=args.url, headers=headers,
                           body=args.data.encode() if args.data else None)

    identities = [parse_identity(s) for s in args.identity]
    if not args.no_unauth and not any(i.strip_auth for i in identities):
        identities.append(Identity(name="unauth", strip_auth=True))

    swaps = parse_swaps(args.swap)
    results = run(base_req, identities, swaps, args.timeout, not args.no_verify)
    print_report(results)

    if args.output:
        # response bodies are never stored, auth headers are never stored, and
        # credential-ish query params in URLs are redacted (_redact_url).
        try:
            with open(args.output, "w") as fh:
                fh.write(json.dumps(results, indent=2))
        except OSError as e:
            sys.exit(f"[!] cannot write output file: {e}")
        print(f"[i] wrote {args.output}")

    hot = any(f["severity"] in ("CRITICAL", "HIGH") for f in results["findings"])
    sys.exit(2 if hot else 0)


if __name__ == "__main__":
    main()
