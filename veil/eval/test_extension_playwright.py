"""
Playwright automated test for Veil Agent Chrome MV3 extension.
Loads unpacked extension in Chrome, opens kyc.html, runs agent with autoApprove,
and verifies form completion and invariants.
"""
import asyncio
import os
import sys
from pathlib import Path

EXTENSION_PATH = str(Path(__file__).resolve().parent.parent / "extension")
KYC_PAGE_PATH = (Path(__file__).resolve().parent / "synthetic_pages" / "kyc.html").as_uri()

async def run_extension_test():
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("[SKIP] Playwright is not installed in the Python environment.")
        return

    print(f"Loading unpacked extension from: {EXTENSION_PATH}")
    print(f"Target KYC page: {KYC_PAGE_PATH}")

    async with async_playwright() as p:
        # Launch Chrome with unpacked MV3 extension
        context = await p.chromium.launch_persistent_context(
            user_data_dir="",  # Temporary in-memory profile
            headless=False,    # Extensions require headful mode in Chromium
            args=[
                f"--disable-extensions-except={EXTENSION_PATH}",
                f"--load-extension={EXTENSION_PATH}",
                "--no-sandbox"
            ]
        )

        page = await context.new_page()
        await page.goto(KYC_PAGE_PATH)
        await page.wait_for_load_state("domcontentloaded")

        # Enable autoApprove in storage for automated test run
        await page.evaluate("""() => {
            const api = globalThis.browser ?? globalThis.chrome;
            return api.storage.local.set({ autoApprove: true });
        }""")

        # Trigger agent run with goal
        await page.evaluate("""() => {
            const api = globalThis.browser ?? globalThis.chrome;
            return api.runtime.sendMessage({ type: 'RUN', goal: 'fill the form and submit' });
        }""")

        # Poll until form is submitted or timeout
        print("Waiting for agent to fill form and submit...")
        success = False
        for _ in range(30):
            await asyncio.sleep(0.5)
            title = await page.title()
            if title == "SUBMITTED":
                success = True
                break

        # Check values
        name_val = await page.input_value('input[name="name"]')
        email_val = await page.input_value('input[name="email"]')
        phone_val = await page.input_value('input[name="phone"]')
        pw_val = await page.input_value('input[name="pw"]')
        title = await page.title()

        print(f"Form field 'name': {name_val}")
        print(f"Form field 'email': {email_val}")
        print(f"Form field 'phone': {phone_val}")
        print(f"Form field 'password': '{pw_val}' (must be empty!)")
        print(f"Page title after submit: {title}")

        assert name_val == "Asha Verma", f"Expected Asha Verma, got {name_val}"
        assert email_val == "asha@example.com", f"Expected asha@example.com, got {email_val}"
        assert phone_val == "9876543210", f"Expected 9876543210, got {phone_val}"
        assert pw_val == "", "INVARIANT VIOLATION: Password field was filled!"
        assert title == "SUBMITTED", f"Expected page title SUBMITTED, got {title}"

        print("\n[SUCCESS] Playwright test verified all form fields filled, password skipped, and form submitted!")
        await context.close()


if __name__ == "__main__":
    asyncio.run(run_extension_test())
