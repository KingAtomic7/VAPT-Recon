#!/usr/bin/env python3
"""Generate LinkedIn post image from HTML template."""

import asyncio
from pathlib import Path
from playwright.async_api import async_playwright


async def generate_linkedin_image():
    """Render the LinkedIn post HTML to PNG at 1200x628."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1200, "height": 628},
            device_scale_factor=2,
        )

        page = await context.new_page()

        # Read the HTML template
        html_path = Path("linkedin_post.html")
        html_content = html_path.read_text(encoding="utf-8")

        await page.set_content(html_content)
        await page.wait_for_timeout(500)

        output_path = Path("docs/linkedin-post.png")
        await page.screenshot(path=str(output_path))
        print(f"Saved LinkedIn image: {output_path}")

        await page.close()
        await browser.close()


if __name__ == "__main__":
    asyncio.run(generate_linkedin_image())