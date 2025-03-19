import sqlite3
import os
from playwright.sync_api import sync_playwright

DB_PATH = os.path.join(os.path.dirname(__file__), 'inventory.db')

def get_siteone_mapped_products():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT barcode, siteone_sku FROM products WHERE siteone_sku IS NOT NULL")
        return c.fetchall()

def update_cost(barcode, price):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("UPDATE products SET cost_per_unit = ? WHERE barcode = ?", (price, barcode))
        conn.commit()
        print(f"✅ Updated {barcode} to ${price:.2f}")

def run_stealth_manual_login_scraper():
    with sync_playwright() as p:
        print("🔐 Launching stealth browser for manual login...")
        browser = p.chromium.launch(headless=False, slow_mo=100)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800},
            device_scale_factor=1,
            is_mobile=False,
            has_touch=False,
            locale="en-US"
        )
        page = context.new_page()

        print("🌐 Opening SiteOne login page...")
        page.goto("https://www.siteone.com/en/login", timeout=60000)

        print("\n👤 Please log in manually in the browser.")
        input("✅ Once you're fully logged in and redirected, press ENTER here to begin scraping...")

        try:
            print("🔄 Navigating to home page to stabilize session...")
            page.goto("https://www.siteone.com/en/home", timeout=10000)
            page.wait_for_timeout(3000)
        except:
            print("⚠️ Home page redirect skipped — continuing anyway.")

        for barcode, sku in get_siteone_mapped_products():
            url = f"https://www.siteone.com/en/p/{sku}"
            try:
                print(f"🔎 Fetching price for SKU {sku}...")
                page.goto(url, timeout=20000)
                page.wait_for_selector(".product-price", timeout=10000)
                price_text = page.locator(".product-price").inner_text()
                price = float(price_text.replace("$", "").replace(",", "").strip())
                update_cost(barcode, price)
            except Exception as e:
                print(f"❌ Failed to update {barcode} from SKU {sku}: {e}")
                page.screenshot(path=f"error_sku_{sku}.png")

        browser.close()

def run_siteone_sync():
    try:
        run_stealth_manual_login_scraper()
        return True, "Prices synced successfully!"
    except Exception as e:
        return False, f"Error during sync: {e}"
