# Bundled country flags

These 40-pixel-wide PNGs cover the country codes in `panel/data/countries.yaml`.
The wizard and dashboard load them from `/static/flags/<lowercase-code>.png`,
not from a third-party image server. They are included in the panel wheel by
`pyproject.toml`'s `static/**/*` package-data rule.

Source: [Flagpedia / FlagCDN](https://flagpedia.net/download/api), downloaded
from `https://flagcdn.com/w40/<code>.png` on 2026-11-07.
[Flagpedia's terms](https://flagpedia.net/terms) state that its flag images are
in the public domain and may be used freely without restriction. This applies
to the flag assets, not to the site's other content.

When adding a country, include its PNG here as well as updating the country
catalog. Tests check that every catalog entry has a locally served PNG.
If a custom country has no bundled image, the UI hides the broken image and
keeps the country code and name visible; it does not request a CDN fallback.
