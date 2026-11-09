#!/usr/bin/env python3
"""Flag domains that sit a small edit distance from a legitimate domain.

This is the fuzzy counterpart to keywords-filtering.py, which only does literal
containment. It catches what containment cannot: typosquats, digit
substitutions and single-character homoglyphs.

Matching compares every label of a domain in the feed against the first label of
each legitimate domain: "army" from army.mil, "armada" from armada.defensa.gob.es.
The rest of a legitimate domain is ignored, because comparing against "mil",
"com" or "gob" would flag the TLD of nearly every domain in the feed. The TLD of
the analysed domain is dropped for the same reason: "net" sits at distance 2
from the brand "nato", so leaving it in would report every .net domain as a
match for nato.int.

Usage:
    python3 levenshtein-filtering.py --domains data/domains.txt --legitimate data/legitimate.txt
    python3 levenshtein-filtering.py ... --max-distance 2 --watch-distance 6

The edit budget for a brand is min(--max-distance, half its length), so short
labels stay strict: "dod" never gets more than one edit, which is why
reuters.com (label "reuters", distance 7) never matches it.

That cap keeps the verdict precise, but it also hides anything above it. So the
distance is always measured anyway, and --watch-distance accepts the domains
that fall just outside the budget as matches too. They keep the match type
"near-miss" so the looser verdict stays visible even though the row says Y.
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


def brand_label(domain):
    """The first label a brand lives in, with any www prefix and the rest dropped."""
    return domain.removeprefix("www.").split(".")[0]


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


def load_legitimate(path, min_length):
    """Unique (domain, brand label) pairs, dropping brands too short to match on."""
    loaded = []
    for line in read_list(path):
        domain = normalize(line)
        if not looks_like_domain(domain):
            continue
        brand = brand_label(domain)
        if brand and len(brand) >= min_length:
            loaded.append((domain, brand))
    return list(dict.fromkeys(loaded))


def levenshtein(left, right):
    """Edit distance between two strings: insertions, deletions and substitutions."""
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for index, char in enumerate(left, 1):
        current = [index]
        for position, other in enumerate(right, 1):
            current.append(min(
                current[-1] + 1,                            # insertion
                previous[position] + 1,                     # deletion
                previous[position - 1] + (char != other),   # substitution
            ))
        previous = current
    return previous[-1]


def labels_of(domain):
    """Labels worth comparing, without the TLD of the analysed domain."""
    labels = [label for label in domain.split(".") if label]
    return labels[:-1] if len(labels) > 1 else labels


def compare(domain, legitimate, max_distance):
    """Return the in-budget hit and the overall nearest brand for one domain.

    Keeping them apart is the point: the hit decides the verdict under the edit
    budget, the nearest keeps a distance for domains that sit outside it.
    """
    # A protected domain outranks a label that also sits at distance 0. Without
    # this, "armada.defensa.gob.es" would be attributed to "defensa.gob.es"
    # purely because that entry appears first in the legitimate list.
    for source, brand in legitimate:
        if source == domain:
            return (source, 0), (source, 0)

    labels = labels_of(domain)
    hit = None
    nearest = None
    for source, brand in legitimate:
        budget = min(max_distance, len(brand) // 2)
        for label in labels:
            distance = levenshtein(label, brand)
            if nearest is None or distance < nearest[1]:
                nearest = (source, distance)
            if distance <= budget and (hit is None or distance < hit[1]):
                hit = (source, distance)
    return hit, nearest


def match_type(distance):
    """Name the verdict from the edit distance."""
    return "identical" if distance == 0 else "fuzzy"


def find_matches(domains, legitimate, max_distance):
    """Return the flagged domains and, for every domain, its nearest brand."""
    hits = {}
    nearest = {}
    for domain in domains:
        hit, close = compare(domain, legitimate, max_distance)
        if hit:
            hits[domain] = hit
        nearest[domain] = close
    return hits, nearest


def is_near_miss(labels, brand, distance, watch_distance):
    """Whether a measured distance is worth reporting even when it falls outside the budget.

    A plain distance ceiling is useless here: at distance 6 unrelated strings pair
    up by chance (bbc.com sits 3 from uscg.mil). So a near miss also has to look
    related: the brand survives inside the label (armada2026.com), the label is a
    fragment of it, the pair is a hair apart, or the brand is long enough that a
    few edits still cannot collide by chance (lockh33dm4r71n).

    The 2 and 10 below were tuned on data/domains.txt: smaller values miss real
    look-alikes, larger ones start pairing unrelated names.
    """
    if distance > watch_distance:
        return False
    if distance <= 2:
        return True
    if any(brand in label or label in brand for label in labels):
        return True
    return len(brand) >= 10 and distance <= len(brand) // 2


def find_near_misses(domains, hits, nearest, watch_distance):
    """Domains outside the edit budget that still sit close to a brand worth reviewing."""
    near_misses = {}
    for domain in domains:
        if domain in hits or not nearest[domain]:
            continue
        source, distance = nearest[domain]
        if is_near_miss(labels_of(domain), brand_label(source), distance, watch_distance):
            near_misses[domain] = nearest[domain]
    return near_misses


def rank(hits):
    """Order domains most suspicious first: smallest distance, then A-Z."""
    return sorted(hits.items(), key=lambda item: (item[1][1], item[0]))


def format_row(cells, widths):
    """Render one pipe delimited row, padded so the columns line up."""
    return "| " + " | ".join(cell.ljust(width) for cell, width in zip(cells, widths)) + " |"


def render(hits, verb="looks like"):
    """One aligned row per hit: | domain | looks like | legitimate | distance |."""
    rows = [
        (domain, verb, source, str(distance))
        for domain, (source, distance) in rank(hits)
    ]
    if not rows:
        return ""
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    return "\n".join(format_row(row, widths) for row in rows)


CSV_HEADER = ("analyzed-domain", "match", "legitimate", "distance", "match-type")
MATCHED = ("identical", "fuzzy", "near-miss")


def unmatched(domains, hits, near_misses):
    """Yield the domains that resembled no legitimate domain, in input order."""
    for domain in domains:
        if domain not in hits and domain not in near_misses:
            yield domain


def analysis_rows(domains, hits, near_misses):
    """Hits first, then near misses, then the unmatched with no measurement."""
    for domain, (source, distance) in rank(hits):
        yield domain, source, distance, match_type(distance)
    for domain, (source, distance) in rank(near_misses):
        yield domain, source, distance, "near-miss"
    for domain in unmatched(domains, hits, near_misses):
        yield domain, "", "", ""


def same_file(path, other):
    """True when both arguments resolve to the same file, symlinks included."""
    return os.path.realpath(path) == os.path.realpath(other)


def write_csv(path, domains, hits, near_misses):
    """Export the whole analysis to a file only its owner can read.

    Exact, fuzzy and near-miss rows are Y, the rest N.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        # RFC 4180 defaults to CRLF, which leaves a stray \r on the last field for
        # cut/awk. Plain \n still parses in Excel, pandas and the csv module.
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(CSV_HEADER)
        writer.writerows(
            (domain, "Y" if kind in MATCHED else "N", source, distance, kind)
            for domain, source, distance, kind in analysis_rows(domains, hits, near_misses)
        )


def render_unmatched(domains, hits, near_misses):
    """Aligned pipe list of the domains that resembled nothing, in input order."""
    rows = list(unmatched(domains, hits, near_misses))
    if not rows:
        return ""
    width = max(len(domain) for domain in rows)
    return "\n".join(f"| {domain.ljust(width)} |" for domain in rows)


def main():
    parser = argparse.ArgumentParser(description="Flag domains near a legitimate domain in edit distance.")
    parser.add_argument("--domains", required=True, help="domain list file, or - for stdin")
    parser.add_argument("--legitimate", required=True, help="legitimate domain list, or - for stdin")
    parser.add_argument("--min-length", type=int, default=3,
                        help="ignore brands shorter than this, they cannot be matched on")
    parser.add_argument("--max-distance", type=int, default=1,
                        help="largest edit distance that still counts as a hit")
    parser.add_argument("--watch-distance", type=int, default=6,
                        help="also match domains whose nearest brand is within this distance")
    parser.add_argument("--show-unmatched", action="store_true",
                        help="also list the domains that matched nothing")
    parser.add_argument("--csv", metavar="PATH", help="export the full analysis to this CSV file")
    args = parser.parse_args()

    if args.min_length < 1:
        sys.exit("error: --min-length must be at least 1")
    if args.max_distance < 0:
        sys.exit("error: --max-distance cannot be negative")
    if args.watch_distance < 0:
        sys.exit("error: --watch-distance cannot be negative")

    # One stdin stream cannot be split into two lists with no separator between
    # them, so refuse the combination instead of draining it on the first read.
    if args.domains == "-" and args.legitimate == "-":
        sys.exit("error: only one of --domains or --legitimate can read from stdin")

    # read_list reports a file that is not valid UTF-8 as ValueError.
    try:
        domains = load_domains(args.domains)
        legitimate = load_legitimate(args.legitimate, args.min_length)
    except (OSError, ValueError) as error:
        sys.exit(f"error: {error}")

    if not legitimate:
        sys.exit(f"error: no usable brand in {args.legitimate} at --min-length {args.min_length}")

    hits, nearest = find_matches(domains, legitimate, args.max_distance)
    near_misses = find_near_misses(domains, hits, nearest, args.watch_distance)

    if args.csv:
        if same_file(args.csv, args.domains) or same_file(args.csv, args.legitimate):
            sys.exit(f"error: --csv {args.csv} would overwrite an input file")
        try:
            write_csv(args.csv, domains, hits, near_misses)
        except OSError as error:
            sys.exit(f"error: cannot write {args.csv}: {error}")

    table = render(hits)
    if table:
        print(table)

    near_miss_table = render(near_misses, "near miss")
    if near_miss_table:
        print(f"\nnear miss, matched (within distance {args.watch_distance}):\n")
        print(near_miss_table)

    if args.show_unmatched:
        clean = render_unmatched(domains, hits, near_misses)
        if clean:
            print(f"\nnot matched ({len(domains) - len(hits) - len(near_misses)}):\n")
            print(clean)

    print(f"\n{len(hits) + len(near_misses)} of {len(domains)} domains matched "
          f"({len(hits)} exact/fuzzy, {len(near_misses)} near miss)", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
