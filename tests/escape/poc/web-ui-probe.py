#!/usr/bin/env python3
# HELD: no script ran, no injected nodes (textContent + CSP). Keep as a regression probe.
# Probe the escrow-web UI for XSS and layout breaks from agent-controlled data.
# usage: web-ui-probe.py <base-url> <user> <pass> <proposal-id> <outdir>
import sys
from playwright.sync_api import sync_playwright

base, user, pw, pid, outdir = sys.argv[1:6]

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    alerts = []
    page.on("dialog", lambda d: (alerts.append(d.message), d.dismiss()))
    page.goto(base)
    page.fill("input[name=user]", user)
    page.fill("input[name=password]", pw)
    page.click("#login-form button")
    page.wait_for_selector("#app:not([hidden])", timeout=10000)
    page.wait_for_timeout(1500)  # let refresh() populate

    # 1) XSS: title must not have been hijacked; no injected elements/handlers
    title = page.title()
    injected_img = page.eval_on_selector_all(
        "img", "els => els.filter(e => e.getAttribute('onerror')).length")
    injected_script = page.eval_on_selector_all(
        "#diff script, #files script, #proposals script", "els => els.length")

    # open the diff for the XSS proposal
    page.evaluate(f"""async () => {{
        const r = await fetch('/api/view', {{method:'POST',
          headers:{{'X-Escrow':'1','Content-Type':'application/json'}},
          body: JSON.stringify({{id:'{pid}',closures:false}})}});
        const j = await r.json();
        window.__renderDiff && window.__renderDiff(j.stdout);
    }}""")
    # click the row instead (renderDiff isn't global); find & click
    page.click(f"#proposals tbody tr:has-text('{pid}')")
    page.wait_for_timeout(1200)
    diff_imgs = page.eval_on_selector_all("#diff img", "e=>e.length")
    diff_scripts = page.eval_on_selector_all("#diff script", "e=>e.length")

    # 2) layout: horizontal overflow of the document = page break for everyone
    metrics = page.evaluate("""() => ({
        scrollW: document.documentElement.scrollWidth,
        clientW: document.documentElement.clientWidth,
        bodyScrollW: document.body.scrollWidth,
    })""")

    page.screenshot(path=outdir + "/full.png", full_page=True)

    print("title      =", repr(title))
    print("alerts     =", alerts)
    print("img[onerror] in DOM =", injected_img)
    print("script in panes     =", injected_script)
    print("#diff img/script    =", diff_imgs, diff_scripts)
    print("layout     =", metrics,
          "OVERFLOW" if metrics["scrollW"] > metrics["clientW"] + 2 else "ok")
    b.close()
