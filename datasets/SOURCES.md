# Sources for the committed name lists

`small_names.txt`, `medium_names.txt` and `large_names.txt` hold names taken from
English Wikipedia article titles. `sample_names.txt` does not: it is a hand-written list of common
given names and surnames that predates the fetcher and carries no third-party licence.

## Attribution

The English Wikipedia publishes these names openly. Its articles and its category
listings are served to anyone without an account, and the MediaWiki API used to
collect them needs no credentials. Wikipedia states its own content licence as
Creative Commons Attribution-Share Alike 4.0.

Wikipedia's contributors license their contributions under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The three
Wikipedia-derived lists remain under that licence, and everything else in this
repository is Apache-2.0.

Each name comes from an article title in the categories listed below. Replace spaces
with underscores and append it to `https://en.wikipedia.org/wiki/` to reach Wikipedia's
article of that name, whose page history lists its authors.

For example, `Darren Cahill` comes from
<https://en.wikipedia.org/wiki/Darren_Cahill>.

Where a qualifier was dropped, the bare name addresses whichever article Wikipedia
holds under that name, which may be a different person who shares it. The source for
those entries is the category listing rather than a single article.

## How the lists were built

`scripts/fetch_notable_people.py` reads titles through the MediaWiki API at
`https://en.wikipedia.org/w/api.php` with `list=categorymembers`.

The primary category is `Category:Living people`. When it does not yield the requested
count the fetcher continues through `Category:20th-century American people`,
`Category:21st-century American people`, `Category:British people`,
`Category:French people` and `Category:German people`.

Only the name is kept. Where an article title carries Wikipedia's trailing qualifier,
as in `Aldair (footballer, born 1996)`, `Aldair` is stored.

The fetcher selects, strips the qualifier, and skips. It reproduces the name as
Wikipedia spells it.

A title is skipped when it names a non-article page, is a disambiguation page, starts
with `List of`, or collapses onto the exact-mode key of a name already kept. That key
is the first 20 letters after non-letters are removed and the rest lowercased, matching
`EXACT_MAX_LEN` in `src/phonetic.h`, which is what makes each list collision-free under
`exact` mode. Dropping the qualifier merges people who share a name, so the fetcher
reads further into the categories to reach each tier's count.

## Provenance

| list | names | snapshot committed |
|---|---|---|
| `small_names.txt` | 65,536 | 2026-06-15 |
| `medium_names.txt` | 131,072 | 2026-05-27 |
| `large_names.txt` | 1,048,576 | 2026-06-15 |

Those dates are the commits that froze each snapshot, and each fetch ran shortly
before. Wikipedia changes continuously, so running the fetcher today yields a different
list.

A sample of 300 committed names checked in September 2026 found 299 resolving to a
live article and one that did not, its article having been renamed or deleted since
the fetch.

To rebuild a list instead of using the committed snapshot:

```bash
python3 scripts/fetch_notable_people.py --count 65536 --output datasets/small_names.txt
```
