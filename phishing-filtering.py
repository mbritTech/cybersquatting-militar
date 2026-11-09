#!/usr/bin/env python3
"""Compare the crafted domain list against a public phishing domain feed.

This is the third phase: phases one and two guess at a domain from its shape,
this one checks it against a list of domains already seen in the wild. The
answer is a plain exact match, no fuzzy work, so a hit here is a domain we
crafted that is also being used for phishing.

The feed is the TweetFeed year.csv dump, a headerless CSV with six columns:
date, user, type, value, tag, source. Rows are kept only when the type is
"domain" and the tag list contains "#phishing", then the value is normalised
and compared to the crafted list.

Usage:
    python3 phishing-filtering.py --domains data/domains.txt --phishing year.csv
    python3 phishing-filtering.py ... --csv phishing-analysis.csv
    python3 phishing-filtering.py ... --type domain --tag scam

The upstream file is large (around 12 MB) and is read line by line, so it never
has to be loaded whole.
"""

import argparse
import csv
import os
import sys
import unicodedata

TYPE_COLUMN = 2
VALUE_COLUMN = 3
TAG_COLUMN = 4
COLUMNS = 6
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


def load_phishing(path, wanted_type, wanted_tag):
    """Unique domains from the feed whose type and tag match, normalized."""
    wanted_type = wanted_type.strip().lower()
    wanted_tag = wanted_tag.strip().lower().lstrip("#")
    found = set()
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        try:
            for row in reader:
                if len(row) < COLUMNS:
                    continue
                if row[TYPE_COLUMN].strip().lower() != wanted_type:
                    continue
                tags = {tag.lstrip("#") for tag in row[TAG_COLUMN].lower().split()}
                if wanted_tag not in tags:
                    continue
                domain = normalize(row[VALUE_COLUMN])
                if looks_like_domain(domain):
                    found.add(domain)
        except csv.Error as error:
            raise ValueError(f"cannot parse {path} as CSV: {error} (line {reader.line_num})") from None
    return found


def compare(crafted, phishing):
    """Split the crafted list into the domains seen in the feed and the rest."""
    found = [domain for domain in crafted if domain in phishing]
    missing = [domain for domain in crafted if domain not in phishing]
    return found, missing


def render(domains, verb):
    """Aligned pipe rows: | domain | verb |."""
    if not domains:
        return ""
    width = max(len(domain) for domain in domains)
    return "\n".join(f"| {domain.ljust(width)} | {verb} |" for domain in domains)


def same_file(path, other):
    """True when both arguments resolve to the same file, symlinks included."""
    return os.path.realpath(path) == os.path.realpath(other)


def write_csv(path, crafted, found):
    """Export the verdict for every crafted domain to a file only its owner can read."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        # RFC 4180 defaults to CRLF, which leaves a stray \r on the last field for
        # cut/awk. Plain \n still parses in Excel, pandas and the csv module.
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("analyzed-domain", "match"))
        writer.writerows(
            (domain, "Y" if domain in found else "N") for domain in crafted
        )


def main():
    parser = argparse.ArgumentParser(description="Match the crafted domains against a phishing feed.")
    parser.add_argument("--domains", required=True, help="crafted domain list, or - for stdin")
    parser.add_argument("--phishing", required=True, help="phishing CSV dump to read")
    parser.add_argument("--type", default="domain", help="feed type column value to keep")
    parser.add_argument("--tag", default="phishing", help="feed tag to keep, without the #")
    parser.add_argument("--show-unmatched", action="store_true",
                        help="also list the crafted domains absent from the feed")
    parser.add_argument("--csv", metavar="PATH", help="export the per-domain verdict to this CSV file")
    args = parser.parse_args()

    # read_list and load_phishing report undecodable input as ValueError.
    try:
        crafted = load_domains(args.domains)
        phishing = load_phishing(args.phishing, args.type, args.tag)
    except (OSError, ValueError) as error:
        sys.exit(f"error: {error}")

    if not crafted:
        sys.exit(f"error: no usable domain in {args.domains}")
    if not phishing:
        sys.exit(f"error: no {args.type} row tagged #{args.tag} in {args.phishing}")

    found, missing = compare(crafted, phishing)

    if args.csv:
        if same_file(args.csv, args.domains) or same_file(args.csv, args.phishing):
            sys.exit(f"error: --csv {args.csv} would overwrite an input file")
        try:
            write_csv(args.csv, crafted, found)
        except OSError as error:
            sys.exit(f"error: cannot write {args.csv}: {error}")

    if found:
        print(render(found, "phishing"))
    else:
        print(f"none of the {len(crafted)} crafted domains appear among the "
              f"{len(phishing)} phishing domains")

    if args.show_unmatched:
        table = render(missing, "clear")
        if table:
            print(f"\nnot in the feed ({len(missing)}):\n")
            print(table)

    print(f"\n{len(found)} of {len(crafted)} crafted domains matched "
          f"against {len(phishing)} phishing domains", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
