#!/usr/bin/env python3
# FIXED in 1561790 (renderDiff walks hunks by their @@ counts): ++/-- lines were styled as headers and left out of the stat.
# Show how the client classifies each rendered diff line + the +/- summary,
# for a proposal whose added lines begin with '+'.
# usage: web-ui-diffclass.py <base-url> <user> <pass> <proposal-id> <outdir>
import sys
from playwright.sync_api import sync_playwright
base, user, pw, pid, outdir = sys.argv[1:6]
with sync_playwright() as p:
    b = p.chromium.launch(); page = b.new_page()
    page.goto(base)
    page.fill("input[name=user]", user); page.fill("input[name=password]", pw)
    page.click("#login-form button")
    page.wait_for_selector("#app:not([hidden])", timeout=10000)
    page.wait_for_timeout(1200)
    page.click(f"#proposals tbody tr:has-text('{pid}')")
    page.wait_for_selector("#diff .diff-line", timeout=8000)
    page.wait_for_timeout(600)
    rows = page.eval_on_selector_all("#diff .diff-line",
        "els => els.map(e => [e.className.replace('diff-line ',''), e.textContent])")
    stat = page.inner_text("#diff-stat")
    # computed style of the backdoor line (muted vs green)
    colors = page.evaluate("""() => {
      const out = {};
      for (const e of document.querySelectorAll('#diff .diff-line')) {
        if (e.textContent.includes('backdoor')) out.backdoor = getComputedStyle(e).backgroundColor + ' / ' + getComputedStyle(e).color;
        if (e.textContent.includes('visible marker')) out.visible = getComputedStyle(e).backgroundColor + ' / ' + getComputedStyle(e).color;
      }
      return out;
    }""")
    page.screenshot(path=outdir + "/diffclass.png", full_page=True)
    print("DIFF-STAT:", repr(stat))
    print("backdoor line style (bg/fg):", colors.get("backdoor"))
    print("visible  line style (bg/fg):", colors.get("visible"))
    print("--- rendered lines (class | text) ---")
    for c, t in rows:
        print(f"{c:8} | {t}")
    b.close()
