try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

import logging

logger = logging.getLogger('SeaScanner.Browser')

class BrowserManager:
    def __init__(self, headless: bool = True, max_contexts: int = 3):
        self._playwright = None
        self._browser = None
        self._contexts = []
        self._context_index = 0
        self.headless = headless
        self.max_contexts = max_contexts
        self._closed = False

    def start(self):
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed — JS crawling unavailable")
            return False
        if self._playwright is not None:
            logger.info("Browser already started")
            return True
        try:
            logger.info("Launching Playwright Chromium browser (headless=%s)...", self.headless)
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            for i in range(self.max_contexts):
                ctx = self._browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    user_agent="SeaScanner/1.0",
                    ignore_https_errors=True,
                )
                self._contexts.append(ctx)
            logger.info("Browser launched successfully with %d contexts", self.max_contexts)
            return True
        except Exception as e:
            logger.error("Browser launch failed: %s", str(e))
            self._closed = True
            return False

    def get_page(self):
        if self._closed or not self._contexts:
            return None
        ctx = self._contexts[self._context_index % len(self._contexts)]
        self._context_index += 1
        page = ctx.new_page()
        return page

    def close_page(self, page):
        try:
            page.close()
        except Exception:
            pass

    def stop(self):
        if self._closed:
            return
        self._closed = True
        try:
            for ctx in self._contexts:
                try:
                    ctx.close()
                except Exception:
                    pass
            self._contexts = []
            if self._browser:
                try:
                    self._browser.close()
                except Exception:
                    pass
                self._browser = None
            if self._playwright:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None
        except Exception:
            pass

    @property
    def is_available(self) -> bool:
        return PLAYWRIGHT_AVAILABLE and not self._closed and self._browser is not None
