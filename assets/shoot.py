"""Render the DriftLock hero visuals (portrait for LinkedIn + wide for README) at 2x."""
import pathlib
from playwright.sync_api import sync_playwright

BASE = pathlib.Path(__file__).resolve().parent
HTML = (BASE / "hero.html").as_uri()

with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge")
    pg = b.new_page(viewport={"width": 1360, "height": 1500}, device_scale_factor=2)
    pg.goto(HTML, wait_until="networkidle")
    pg.wait_for_timeout(900)  # let webfonts settle
    pg.locator("#portrait").screenshot(path=str(BASE / "linkedin.png"))
    pg.locator("#wide").screenshot(path=str(BASE / "hero.png"))
    b.close()
print("rendered linkedin.png + hero.png")
