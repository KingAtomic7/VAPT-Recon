#!/usr/bin/env python3
"""Generate terminal demo screenshot using Playwright."""

import asyncio
from pathlib import Path
from playwright.async_api import async_playwright


async def capture_terminal_demo(docs_dir: Path):
    """Capture terminal demo showing CLI in action."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1000, "height": 600},
            device_scale_factor=2,
        )

        page = await context.new_page()

        # Create a terminal-like HTML page showing the demo
        terminal_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>vapt-recon Demo</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            background: #1e1e1e;
            font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
            font-size: 14px;
            line-height: 1.5;
            color: #d4d4d4;
        }}
        .terminal {{
            background: #1e1e1e;
            border: 1px solid #3c3c3c;
            border-radius: 6px;
            overflow: hidden;
        }}
        .terminal-header {{
            background: #2d2d2d;
            padding: 8px 12px;
            border-bottom: 1px solid #3c3c3c;
            display: flex;
            gap: 8px;
        }}
        .terminal-button {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        .btn-close {{ background: #ff5f56; }}
        .btn-minimize {{ background: #ffbd2e; }}
        .btn-maximize {{ background: #27c93f; }}
        .terminal-body {{
            padding: 16px 20px;
            white-space: pre-wrap;
        }}
        .prompt {{ color: #89d185; }}
        .command {{ color: #dcdcaa; }}
        .output {{ color: #9cdcfe; }}
        .banner {{
            color: #4ec9b0;
            border: 1px solid #4ec9b0;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .progress-bar {{
            display: inline-block;
            width: 300px;
            height: 16px;
            background: #3c3c3c;
            border-radius: 8px;
            overflow: hidden;
            margin: 5px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #4ec9b0, #89d185);
            transition: width 0.3s ease;
        }}
        .summary-table {{
            border-collapse: collapse;
            margin: 10px 0;
        }}
        .summary-table td {{
            padding: 4px 12px;
            border-bottom: 1px solid #3c3c3c;
        }}
        .summary-table td:first-child {{
            color: #9cdcfe;
        }}
        .finding-critical {{ color: #f44747; }}
        .finding-high {{ color: #ff8c00; }}
        .finding-medium {{ color: #ffcc00; }}
        .finding-low {{ color: #4ec9b0; }}
        .finding-info {{ color: #9cdcfe; }}
    </style>
</head>
<body>
    <div class="terminal">
        <div class="terminal-header">
            <span class="terminal-button btn-close"></span>
            <span class="terminal-button btn-minimize"></span>
            <span class="terminal-button btn-maximize"></span>
        </div>
        <div class="terminal-body">
<span class="prompt">user@host:~$ </span><span class="command">vapt-recon scan example.com --profile quick --report html</span>

<div class="banner">
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃         vapt-recon - QUICK scan                ┃
┃ Target: example.com                            ┃
┃ Reports: html                                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
</div>

Overall Progress: <span class="output">0%</span> |<div class="progress-bar"><div class="progress-fill" style="width:0%"></div></div>|
Subdomain Enum:   <span class="output">10%</span> |<div class="progress-bar"><div class="progress-fill" style="width:10%"></div></div>| Starting...
Subdomain Enum:   <span class="output">60%</span> |<div class="progress-bar"><div class="progress-fill" style="width:60%"></div></div>| Found 42 subdomains
Subdomain Enum:  <span class="output">100%</span> |<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>| Completed: 42 subdomains

Overall Progress: <span class="output">15%</span> |<div class="progress-bar"><div class="progress-fill" style="width:15%"></div></div>|
Port Scan:        <span class="output">30%</span> |<div class="progress-bar"><div class="progress-fill" style="width:30%"></div></div>| Running naabu...
Port Scan:        <span class="output">100%</span> |<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>| Completed: 18 services

Overall Progress: <span class="output">40%</span> |<div class="progress-bar"><div class="progress-fill" style="width:40%"></div></div>|
Tech Fingerprint: <span class="output">20%</span> |<div class="progress-bar"><div class="progress-fill" style="width:20%"></div></div>| Running httpx...
Tech Fingerprint: <span class="output">100%</span> |<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>| Completed: 12 technologies

Overall Progress: <span class="output">55%</span> |<div class="progress-bar"><div class="progress-fill" style="width:55%"></div></div>|
Vuln Scan:        <span class="output">10%</span> |<div class="progress-bar"><div class="progress-fill" style="width:10%"></div></div>| Running nuclei...
Vuln Scan:        <span class="output">80%</span> |<div class="progress-bar"><div class="progress-fill" style="width:80%"></div></div>| Found 5 findings
Vuln Scan:        <span class="output">100%</span> |<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>| Completed: 5 findings

Overall Progress: <span class="output">85%</span> |<div class="progress-bar"><div class="progress-fill" style="width:85%"></div></div>|
Reports:         <span class="output">100%</span> |<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>| Reports generated

Overall Progress:<span class="output">100%</span> |<div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div>|

<div class="banner">
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Scan Summary: example.com                      ┃
┠────────────────────────────────────────────────┨
┃ Metric        │ Count                         ┃
┠───────────────┼───────────────────────────────┨
┃ Subdomains    │ 42                            ┃
┃ Services      │ 18                            ┃
┃ Technologies  │ 12                            ┃
┃ Findings      │ 5                             ┃
┃   Critical    │ 1                             ┃
┃   High        │ 2                             ┃
┃   Medium      │ 2                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
</div>

<span class="output">✓ Reports saved to ./reports</span>
<span class="prompt">user@host:~$ </span>
        </div>
    </div>
</body>
</html>
        """
        await page.set_content(terminal_html)
        await page.wait_for_timeout(500)

        await page.screenshot(path=str(docs_dir / "terminal-demo.png"), full_page=False)
        print(f"Saved terminal demo: {docs_dir / 'terminal-demo.png'}")

        await page.close()
        await browser.close()


async def main():
    docs_dir = Path("./docs")
    docs_dir.mkdir(exist_ok=True)

    print("Generating terminal demo screenshot...")
    await capture_terminal_demo(docs_dir)
    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())