# Leaflet 1.9.4 (vendored)

The dashboard's map library, served by the sniffer itself at
`/vendor/leaflet/` so the dashboard works without internet (field use, the
Android app in airplane mode). Before, it came from unpkg.com, and with no
network the whole dashboard script stopped at the first map call.

Files are `dist/leaflet.js`, `dist/leaflet.css`, `dist/images/*.png` and
`LICENSE` from the npm package `leaflet@1.9.4`, unmodified. The tarball's
sha512 matched the registry's integrity value
`sha512-nxS1ynzJOmOlHp+iL3FyWqK89GtNL8U8rvlMOsQdTTssxZwCXh8N2NB3GDQOL+YR3XnWyZAxwQixURb+FA74PA==`.

Leaflet is BSD-2-Clause (see LICENSE). After changing these files, run
`python3 tools/gen_web_assets.py` to regenerate `web_assets.c`.
