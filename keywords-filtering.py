#!/usr/bin/env python3
"""Flag domains that contain a brand keyword. Literal containment only.

Usage:
    python3 keywords-filtering.py --domains data/domains.txt --keywords data/keywords.txt
    cat domains.txt | python3 keywords-filtering.py --domains - --keywords keywords.txt
"""

import argparse
import csv
import os
import sys
import unicodedata

MAX_DOMAIN_LENGTH = 253  # DNS limit for a domain name in presentation form.


# normalize, read_list, looks_like_domain and load_domains are duplicated
# verbatim in the three phase scripts: change all three together.
def normalize(value):
    """Return a comparable hostname token, folded and stripped of URL noise.

    Order matters: format characters are dropped first, NFKC folds fullwidth and
    other compatibility forms ("ａｒｍｙ" becomes "army"), casefold normalises
    case ("ß" becomes "ss"), then scheme, wildcard, path, query, fragment and
    trailing dot are removed, and runs of whitespace collapse to one space.
    """
    text = "".join(ch for ch in value if unicodedata.category(ch) != "Cf")
    text = unicodedata.normalize("NFKC", text).strip().casefold()
    if "://" in text:
        text = text.split("://", 1)[1]
    for separator in ("/", "?", "#"):
        text = text.split(separator, 1)[0]
    if text.startswith("*."):
        text = text[2:]
    return " ".join(text.rstrip(".").split())


def read_list(path):
    """Return trimmed lines from a file (or stdin for '-'), without blanks or '#' comments."""
    try:
        if path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(path, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
    except UnicodeDecodeError:
        raise ValueError(f"{path} is not valid UTF-8") from None
    stripped = (line.strip() for line in lines)
    return [line for line in stripped if line and not line.startswith("#")]


def looks_like_domain(value):
    """Cheap junk check, and the sanitizer that keeps the report safe.

    Only letters, digits, "-" and "." survive, so a crafted value cannot carry a
    CSV formula, a terminal escape or a path separator into the output.
    """
    if len(value) > MAX_DOMAIN_LENGTH:
        return False
    return "." in value and " " not in value and all(c.isalnum() or c in "-." for c in value)


def load_domains(path):
    """Unique domains in input order; one line may hold several, comma separated.

    dict.fromkeys dedupes while keeping the first sighting, so the report keeps
    the order of the file.
    """
    domains = []
    for line in read_list(path):
        for candidate in line.split(","):
            domain = normalize(candidate)
            if looks_like_domain(domain):
                domains.append(domain)
    return list(dict.fromkeys(domains))


def load_keywords(path, min_length):
    """Normalized unique keywords, dropping the ones too short to be meaningful."""
    keywords = [normalize(line) for line in read_list(path)]
    return list(dict.fromkeys(k for k in keywords if len(k) >= min_length))


def match_type(domain, keyword):
    """Return 'exact', 'contains', 'token-all', or None when the keyword is absent."""
    # Only brand.tld (optionally behind www) is a genuine owner; a deeper host is an
    # impostor, so "first label == keyword" alone must not earn an 'exact' verdict.
    bare = domain.removeprefix("www.")
    labels = bare.split(".")
    if bare == keyword or (len(labels) == 2 and labels[0] == keyword):
        return "exact"
    if keyword in domain.rsplit(".", 1)[0]:  # label only, so a keyword cannot match a TLD
        return "contains"
    if all(token in domain for token in keyword.split()):
        return "token-all"
    return None


def find_matches(domains, keywords):
    """Map every flagged domain to its (keyword, match type) hits."""
    hits = {}
    for domain in domains:
        for keyword in keywords:
            kind = match_type(domain, keyword)
            if kind:
                hits.setdefault(domain, []).append((keyword, kind))
    return hits


def rank(hits):
    """Order domains most suspicious first: most keywords, then longest, then A-Z."""
    return sorted(
        hits.items(),
        key=lambda item: (-len(item[1]), -max(len(k) for k, _ in item[1]), item[0]),
    )


def format_row(cells, widths):
    """Render one pipe delimited row, padded so the columns line up."""
    return "| " + " | ".join(cell.ljust(width) for cell, width in zip(cells, widths)) + " |"


def render(hits):
    """One aligned row per hit: | domain | matches | keyword | type |."""
    rows = [
        (domain, "matches", keyword, kind)
        for domain, pairs in rank(hits)
        for keyword, kind in pairs
    ]
    if not rows:
        return ""
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    return "\n".join(format_row(row, widths) for row in rows)


CSV_HEADER = ("analyzed-domain", "match", "keyword", "match-type")


def unmatched(domains, hits):
    """Yield the domains that no keyword matched, in input order."""
    for domain in domains:
        if domain not in hits:
            yield domain


def analysis_rows(domains, hits):
    """Yield every hit as (domain, keyword, match type), then the unmatched domains last."""
    for domain, pairs in rank(hits):
        for keyword, kind in pairs:
            yield domain, keyword, kind
    for domain in unmatched(domains, hits):
        yield domain, "", ""


def same_file(path, other):
    """True when both arguments resolve to the same file, symlinks included."""
    return os.path.realpath(path) == os.path.realpath(other)


def write_csv(path, domains, hits):
    """Export the whole analysis to a file only its owner can read."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        # RFC 4180 defaults to CRLF, which leaves a stray \r on the last field for
        # cut/awk. Plain \n still parses in Excel, pandas and the csv module.
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(CSV_HEADER)
        writer.writerows(
            (domain, "Y" if keyword else "N", keyword, kind)
            for domain, keyword, kind in analysis_rows(domains, hits)
        )


def render_unmatched(domains, hits):
    """Aligned pipe list of the domains no keyword matched, in input order."""
    rows = list(unmatched(domains, hits))
    if not rows:
        return ""
    width = max(len(domain) for domain in rows)
    return "\n".join(f"| {domain.ljust(width)} |" for domain in rows)


def main():
    parser = argparse.ArgumentParser(description="Flag domains containing a brand keyword.")
    parser.add_argument("--domains", required=True, help="domain list file, or - for stdin")
    parser.add_argument("--keywords", required=True, help="keyword list file, or - for stdin")
    parser.add_argument("--min-length", type=int, default=4, help="ignore keywords shorter than this")
    parser.add_argument("--show-unmatched", action="store_true",
                        help="also list the domains that matched no keyword")
    parser.add_argument("--csv", metavar="PATH", help="export the full analysis to this CSV file")
    args = parser.parse_args()

    if args.min_length < 1:
        sys.exit("error: --min-length must be at least 1")
    if args.domains == "-" and args.keywords == "-":
        sys.exit("error: only one of --domains or --keywords can read from stdin")

    # read_list reports a file that is not valid UTF-8 as ValueError.
    try:
        domains = load_domains(args.domains)
        keywords = load_keywords(args.keywords, args.min_length)
    except (OSError, ValueError) as error:
        sys.exit(f"error: {error}")

    if not keywords:
        sys.exit(f"error: no usable keyword in {args.keywords} at --min-length {args.min_length}")

    hits = find_matches(domains, keywords)

    if args.csv:
        if same_file(args.csv, args.domains) or same_file(args.csv, args.keywords):
            sys.exit(f"error: --csv {args.csv} would overwrite an input file")
        try:
            write_csv(args.csv, domains, hits)
        except OSError as error:
            sys.exit(f"error: cannot write {args.csv}: {error}")

    table = render(hits)
    if table:
        print(table)

    if args.show_unmatched:
        unmatched = render_unmatched(domains, hits)
        if unmatched:
            print(f"\nnot matched ({len(domains) - len(hits)}):\n")
            print(unmatched)

    print(f"\n{len(hits)} of {len(domains)} domains flagged", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
