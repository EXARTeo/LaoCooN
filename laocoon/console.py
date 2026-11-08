"""⑤ Audit & control, the web pages: the console, the policy studio, the welcome page and the operator sign-in.

Each page is one static HTML file in `static/`, served self-contained (no external assets): shared CSS/JS
partials are inlined with `<!--#include name-->`, and `__PLACEHOLDERS__` are substituted at serve time.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from urllib.parse import quote

from .config import env

STATIC = Path(__file__).resolve().parent / "static"
_INCLUDE = re.compile(r"<!--#include ([A-Za-z0-9_.-]+)-->")

# The product name and logo: every page follows them. LAOCOON_BRAND_NAME overrides the name; static/logo.svg is
# the header mark (the heavier small-size cut of brand/laocoon-mark.svg, coloured by CSS) and static/favicon.svg
# the tab icon; static/mark-line.svg is the thin cut for the large mark of the sign-in page.
BRAND_NAME = "Laocoon"


def brand() -> dict:
    name = env("LAOCOON_BRAND_NAME") or BRAND_NAME
    fav = STATIC / "favicon.svg"
    icon = "data:image/svg+xml," + quote(fav.read_text(encoding="utf-8").strip()) if fav.is_file() else ""
    logo = STATIC / "logo.svg"
    if logo.is_file():
        mark = logo.read_text(encoding="utf-8")
    else:                                                    # placeholder monogram until there is a logo
        mark = ('<svg viewBox="0 0 32 32" aria-hidden="true" class="mark"><rect x="1.5" y="1.5" width="29" '
                'height="29" rx="7" fill="none" stroke="currentColor" stroke-width="2"/><text x="16" y="21.5" '
                'text-anchor="middle" font-size="15" font-weight="700" fill="currentColor" '
                'font-family="system-ui,sans-serif">' + html.escape(name[:1].upper()) + '</text></svg>')
    line = STATIC / "mark-line.svg"                         # the thin cut, for the mark drawn large (sign-in page)
    art = line.read_text(encoding="utf-8") if line.is_file() else mark
    return {"name": name, "mark": mark, "icon": icon, "art": art}


def _script_safe(value: str) -> str:
    return value.replace('"', "").replace("<", "").replace("\\", "")


def render(page: str, **subs) -> str:
    """Inline the partials, then substitute __KEY__ placeholders. Values are HTML-escaped, except: keys ending
    in _RAW (trusted markup), _JSON (serialised for a <script type="application/json"> block) and API_BASE
    (goes into a JS string literal)."""
    text = (STATIC / page).read_text(encoding="utf-8")
    text = _INCLUDE.sub(lambda m: (STATIC / m.group(1)).read_text(encoding="utf-8"), text)
    b = brand()
    subs = {"BRAND": b["name"], "BRAND_MARK_RAW": b["mark"], "BRAND_ART_RAW": b["art"], "BRAND_ICON": b["icon"], **subs}
    for key, value in subs.items():
        if key.endswith("_JSON"):
            value = json.dumps(value, ensure_ascii=False).replace("</", "<\\/")
        elif key == "API_BASE":
            value = _script_safe(str(value))
        elif not key.endswith("_RAW"):
            value = html.escape(str(value))
        text = text.replace(f"__{key}__", value)
    return text


def console_html(api_base: str, title: str = "Laocoon", *, nav: dict | None = None) -> str:
    """The operator console. `nav` = {"policies": url, "home": url} links the other pages (the proxy has them)."""
    return render("console.html", API_BASE=api_base, TITLE=title, NAV_JSON=nav or {})


def policies_html(api_base: str, title: str = "Laocoon", *, nav: dict | None = None) -> str:
    return render("policies.html", API_BASE=api_base, TITLE=title, NAV_JSON=nav or {})


def settings_html(api_base: str, title: str = "Laocoon", *, nav: dict | None = None) -> str:
    """Mitigations: the runtime switches of laocoon/runtime.py (GET/PUT {api_base}/settings)."""
    return render("settings.html", API_BASE=api_base, TITLE=title, NAV_JSON=nav or {})


def login_html(api_base: str, *, next_url: str = "/laocoon", demo: bool = False, token_login: bool = False,
               nav: dict | None = None) -> str:
    """Operator sign-in. `demo`: the built-in demo account is active, so the page shows it."""
    return render("login.html", API_BASE=api_base, NEXT=next_url, NAV_JSON=nav or {},
                  LOGIN_JSON={"demo": demo, "token": token_login})


def welcome_html(*, console_url: str = "/laocoon", policies_url: str = "/laocoon/policies",
                 metrics: dict | None = None, app_url: str = "", nav: dict | None = None) -> str:
    """The public landing page. `app_url` (optional) links the protected application itself."""
    return render("welcome.html", CONSOLE_URL=console_url, POLICIES_URL=policies_url, APP_URL=app_url or "",
                  METRICS_JSON=metrics or {}, NAV_JSON=nav or {})
