"""Playwright-driven screenshotting of alive endpoints.

Screenshots are captured with a headless Chromium and stored back onto each
``Endpoint`` as a base64-encoded PNG (no data-uri prefix). Playwright is
imported lazily so the rest of Snapmap works even when it is not installed.
"""

from __future__ import annotations

import asyncio
import base64

from .models import Endpoint, Options

_INSTALL_HINT = (
    "Screenshots skipped: Chromium is unavailable. Install it with "
    "`playwright install chromium`."
)


async def capture_all(endpoints: list[Endpoint], opts: Options, log=print) -> None:
    """Screenshot every alive endpoint in place (fills ``ep.screenshot``).

    On missing Playwright or a Chromium launch failure a hint is logged and the
    function returns without raising. Individual page failures never abort the
    batch.
    """
    targets = [ep for ep in endpoints if ep.alive]
    if not targets:
        return

    try:
        from playwright.async_api import (
            TimeoutError as PlaywrightTimeout,
            async_playwright,
        )
    except ImportError:
        log(_INSTALL_HINT)
        return

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--ignore-certificate-errors", "--no-sandbox"],
            )
        except Exception as exc:  # launch failure (e.g. browser not installed)
            log(f"{_INSTALL_HINT} ({exc})")
            return

        sem = asyncio.Semaphore(opts.screenshot_concurrency)

        async def shoot(ep: Endpoint) -> None:
            async with sem:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800},
                )
                try:
                    page = await context.new_page()
                    try:
                        # 'load' waits for sub-resources; 'domcontentloaded' fires too
                        # early and often paints blank for JS-rendered / redirecting pages.
                        await page.goto(
                            ep.final_url or ep.url,
                            wait_until="load",
                            timeout=opts.screenshot_timeout,
                        )
                    except PlaywrightTimeout:
                        pass  # slow page: capture whatever has rendered so far
                    # let late XHR / client-side painting settle to avoid blank captures
                    try:
                        await page.wait_for_load_state(
                            "networkidle", timeout=min(6000, opts.screenshot_timeout)
                        )
                    except PlaywrightTimeout:
                        pass
                    await page.wait_for_timeout(opts.screenshot_delay or 800)
                    png = await page.screenshot(
                        full_page=opts.full_page, timeout=opts.screenshot_timeout
                    )
                    ep.screenshot = base64.b64encode(png).decode("ascii")
                except Exception as exc:
                    log(f"screenshot failed for {ep.url}: {exc}")
                finally:
                    await context.close()

        try:
            await asyncio.gather(*(shoot(ep) for ep in targets))
        finally:
            await browser.close()
