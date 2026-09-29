#!/usr/bin/env python3
"""Observe a formula's signed dependency closure without transferring bottles."""
import argparse
from collections import deque
import json
import re
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="middles public URL, including any deployment prefix")
    parser.add_argument("formula", nargs="+")
    parser.add_argument("--max-formulas", type=int, default=256)
    args = parser.parse_args()
    u = urllib.parse.urlsplit(args.base_url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
        parser.error("base_url must be HTTP(S), without credentials/query/fragment")
    if not 1 <= args.max_formulas <= 2000:
        parser.error("max-formulas must be within 1-2000")
    valid = re.compile(r"[a-z0-9][a-z0-9@+._-]{0,213}\Z")
    if any(not valid.fullmatch(f) for f in args.formula):
        parser.error("invalid formula name")
    pending, seen, failed = deque(args.formula), set(), []
    opener = urllib.request.build_opener(NoRedirect())
    while pending:
        formula = pending.popleft()
        if formula in seen:
            continue
        if len(seen) >= args.max_formulas:
            raise SystemExit("dependency closure exceeds max-formulas; increase the explicit limit")
        seen.add(formula)
        url = args.base_url.rstrip("/") + "/homebrew/warm/" + urllib.parse.quote(formula, safe="@+")
        try:
            with opener.open(url, timeout=90) as response:
                body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError("warming response too large")
            data = json.loads(body)
            dependencies = data["dependencies"]
            if not isinstance(dependencies, list) or len(dependencies) > 1000 or any(not isinstance(d, str) or not valid.fullmatch(d) for d in dependencies):
                raise ValueError("invalid dependency response")
            for bottle in data["bottles"]:
                print(f'{formula} {bottle["platform"]}: eligible={bottle["eligible"]}, eligible_at={bottle["eligible_at"]}', flush=True)
            pending.extend(dependencies)
        except (urllib.error.URLError, ValueError, KeyError) as error:
            failed.append(formula)
            print(f"{formula}: warming failed ({error})", flush=True)
    print(f"Observed {len(seen) - len(failed)} formulae; {len(failed)} failures.")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
