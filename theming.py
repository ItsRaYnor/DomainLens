"""Theme resolution: which palette a page renders with, and in whose accent.

Two constraints shape this module.

The theme has to be on <html> before the first paint, or the page flashes the
wrong palette on every navigation. The usual trick is a tiny inline script in
<head>; this app serves `script-src 'self'` with no `unsafe-inline`, so that
script would simply never run. The server therefore renders the attribute
itself, and `resolve()` is what it asks.

The accent is a colour that ends up inside a `style` attribute. A colour
arriving from a cookie, a form or a settings file is untrusted text, and text
interpolated into CSS is an injection vector — `#fff;background:url(//evil)`
is a valid-looking string and a working exfiltration. So `normalize_accent()`
is strict: it returns a six-digit hex value or nothing at all, and everything
downstream only ever sees its output.
"""

from __future__ import annotations

import colorsys
import re

THEMES = ("auto", "light", "dark")
DEFAULT_THEME = "auto"
DEFAULT_ACCENT = "#5b8def"

THEME_COOKIE = "dl_theme"
ACCENT_COOKIE = "dl_accent"

# One year: a display preference is not security state and re-asking for it
# every session is the annoyance the setting existed to remove.
COOKIE_MAX_AGE = 365 * 24 * 3600

_HEX_LONG = re.compile(r"^#([0-9a-fA-F]{6})$")
_HEX_SHORT = re.compile(r"^#([0-9a-fA-F]{3})$")


def normalize_theme(value):
    """Return a known theme name, or None.

    None rather than a default on purpose: the caller needs to tell "this
    layer has no opinion" from "this layer says auto", so that a user who
    picked auto is not silently overridden by an admin default.
    """
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if value in THEMES else None


def normalize_accent(value):
    """Return a canonical `#rrggbb`, or None if it is not exactly that."""
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    match = _HEX_LONG.match(value)
    if match:
        return "#" + match.group(1)
    match = _HEX_SHORT.match(value)
    if match:
        # Expanded rather than passed through: half-accepting shorthand means
        # two spellings of one colour reaching storage and comparisons.
        return "#" + "".join(ch * 2 for ch in match.group(1))
    return None


def accent_hs(value):
    """Hue and saturation of a colour, as CSS units. None if it is not one.

    Lightness is deliberately dropped. It belongs to the theme: a colour
    picked while in light mode would otherwise stay dark in dark mode, where
    it is unreadable against the page. Keeping only hue and saturation is
    what lets one pick work in both.
    """
    normalized = normalize_accent(value)
    if not normalized:
        return None
    r = int(normalized[1:3], 16) / 255
    g = int(normalized[3:5], 16) / 255
    b = int(normalized[5:7], 16) / 255
    hue, _lightness, saturation = colorsys.rgb_to_hls(r, g, b)
    return round(hue * 360), round(saturation * 100)


def accent_style(value):
    """The `style` attribute body that applies a custom accent, or ""."""
    parts = accent_hs(value)
    if not parts:
        return ""
    hue, saturation = parts
    # A grey has no meaningful hue, and forcing saturation to 0 would leave
    # the interface with no accent at all — every state colour would read as
    # disabled. Below this point we keep the default accent instead.
    if saturation < 8:
        return ""
    return f"--accent-h:{hue};--accent-s:{saturation}%"


def resolve(*, user=None, cookies=None, defaults=None):
    """Work out the theme and accent for this request.

    Order: what the signed-in user chose, then what this browser chose, then
    what the administrator set as the default. The cookie is not merely a
    fallback for anonymous visitors — running with authentication disabled
    entirely is a supported configuration, and there is no user record to
    read in that case.
    """
    cookies = cookies or {}
    defaults = defaults or {}

    prefs = (user or {}).get("prefs") or {}
    if not isinstance(prefs, dict):
        prefs = {}

    theme = (normalize_theme(prefs.get("theme"))
             or normalize_theme(cookies.get(THEME_COOKIE))
             or normalize_theme(defaults.get("theme"))
             or DEFAULT_THEME)

    accent = (normalize_accent(prefs.get("accent"))
              or normalize_accent(cookies.get(ACCENT_COOKIE))
              or normalize_accent(defaults.get("accent"))
              or DEFAULT_ACCENT)

    return {"theme": theme, "accent": accent}


def html_attributes(resolved):
    """The attributes for <html>, ready to render.

    "auto" produces no `data-theme` at all. That absence is what hands the
    decision to `prefers-color-scheme`; stamping `data-theme="auto"` would be
    a fourth state that matches none of the CSS blocks and would leave the
    page on the light palette regardless of the operating system.
    """
    out = ""
    theme = resolved.get("theme")
    if theme in ("light", "dark"):
        out += f' data-theme="{theme}"'
    style = accent_style(resolved.get("accent"))
    if style and resolved.get("accent") != DEFAULT_ACCENT:
        out += f' style="{style}"'
    return out
