#!/usr/bin/env python3
"""Checks the localization files: same keys in fa and en, same format placeholders, and every
key used as L("...") in the Swift sources exists. Dynamic keys (state.*, failure.*) are
derived from the Swift enums by naming convention and checked separately."""
import re, sys, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
def load(p):
    d = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^"([^"]+)" = "(.*)";$', line)
        if line.strip() and not m:
            print("bad line in", p, ":", line); sys.exit(1)
        if m: d[m.group(1)] = m.group(2)
    return d

fa = load(root / "App/Resources/fa.lproj/Localizable.strings")
en = load(root / "App/Resources/en.lproj/Localizable.strings")
errors = []
for k in sorted(set(fa) ^ set(en)):
    errors.append("key only in one language: " + k)
ph = lambda s: sorted(re.findall(r"%(?:lld|@|d|s)", s))
for k in set(fa) & set(en):
    if ph(fa[k]) != ph(en[k]):
        errors.append("placeholder mismatch: " + k)
used = set()
for f in list((root / "App").rglob("*.swift")):
    used |= set(re.findall(r'\bL\("([a-z0-9_.]+)"', f.read_text(encoding="utf-8")))
for k in sorted(used - set(fa)):
    errors.append("used but not defined: " + k)
src = (root / "Shared/Logic/ConnectionState.swift").read_text(encoding="utf-8")
codes = [c for c in re.findall(r'return "([a-z_]+)"', src) if not c.endswith("_")]
codes += ["unsupported_amneziawg", "unsupported_openvpn"]
for c in set(codes):
    for suffix in ("title", "message"):
        key = f"failure.{c}.{suffix}"
        if key not in fa: errors.append("missing failure string: " + key)
for s in ("disconnected", "connecting", "connected", "disconnecting", "failed"):
    if "state." + s not in fa: errors.append("missing state." + s)
for e in errors: print("ERROR:", e)
print("ok" if not errors else f"{len(errors)} problem(s)", f"({len(fa)} keys)")
sys.exit(1 if errors else 0)
