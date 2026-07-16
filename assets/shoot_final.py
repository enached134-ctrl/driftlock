"""Render the WaveSpeed-hero + branding overlay to the final LinkedIn visual."""
import pathlib
from playwright.sync_api import sync_playwright

BASE = pathlib.Path(__file__).resolve().parent
HTML = (BASE / "hero-final.html").as_uri()

with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge")
    pg = b.new_page(viewport={"width": 1200, "height": 1500}, device_scale_factor=2)
    pg.goto(HTML, wait_until="networkidle")
    pg.wait_for_timeout(900)
    pg.locator("#card").screenshot(path=str(BASE / "linkedin-final.png"))
    b.close()
print("rendered linkedin-final.png")
