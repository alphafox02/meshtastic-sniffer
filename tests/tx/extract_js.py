"""Pull DASHBOARD_HTML out of web.c (concatenated C string literals), write
the HTML and each inline <script> body so they can be syntax-checked."""
import re
import sys

src = open(sys.argv[1], encoding="utf-8").read()
start = src.index("DASHBOARD_HTML")
start = src.index("=", start) + 1
end = src.index("</html>", start)
end = src.index(";", end)
body = src[start:end]
# drop C comments between literals
body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
lits = re.findall(r'"((?:[^"\\\n]|\\.)*)"', body)
raw = "".join(lits)
html = raw.encode("latin-1", "backslashreplace").decode("unicode_escape")
open(sys.argv[2] + "/dashboard.html", "w", encoding="utf-8").write(html)
scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
for i, s in enumerate(scripts):
    open(f"{sys.argv[2]}/script{i}.js", "w", encoding="utf-8").write(s)
print(f"html {len(html)} bytes, {len(scripts)} inline script(s)")
missing = 0
for needle in ["id=\"tx-box\"", "id=\"tx-config\"", "function txSend", "txInit();",
               "X-Mesh-Tx"]:
    print(("ok   " if needle in html else "FAIL ") + needle)
    missing += needle not in html
sys.exit(1 if missing else 0)
