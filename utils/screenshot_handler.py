"""
Screenshot handling for vulnerability proof of concept
"""

import os
import time
import base64
from typing import Optional, Dict, Any

class ScreenshotHandler:
    """Screenshot handler for vulnerability documentation"""
    
    def __init__(self, screenshots_dir: str = "screenshots"):
        """Initialize screenshot handler"""
        self.screenshots_dir = screenshots_dir
        self.driver = None
        self._ensure_screenshots_dir()
    
    def _ensure_screenshots_dir(self):
        """Ensure screenshots directory exists"""
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)
    
    def _init_driver(self):
        """Initialize Chrome driver with headless options"""
        if self.driver is None:
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                chrome_options.add_argument("--disable-gpu")
                chrome_options.add_argument("--window-size=1920,1080")
                chrome_options.add_argument("--disable-extensions")
                chrome_options.add_argument("--disable-plugins")
                chrome_options.add_argument("--disable-images")
                chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                
                self.driver = webdriver.Chrome(options=chrome_options)
                self.driver.set_page_load_timeout(10)
            except Exception as e:
                print(f"Warning: Could not initialize Chrome driver for screenshots: {e}")
                print("Screenshots will be disabled. Install selenium and chromedriver to enable screenshots.")
                self.driver = None
    
    def take_screenshot(self, url: str, vulnerability_type: str, vuln_id: str) -> Optional[str]:
        """
        Take screenshot of vulnerability
        Returns: screenshot filename or None if failed
        """
        try:
            self._init_driver()
            if self.driver is None:
                return None
            
            # Generate filename
            timestamp = int(time.time())
            filename = f"{vulnerability_type}_{vuln_id}_{timestamp}.png"
            filepath = os.path.join(self.screenshots_dir, filename)
            
            # Navigate to URL
            self.driver.get(url)
            
            # Wait a bit for page to load
            time.sleep(2)
            
            # Take screenshot
            self.driver.save_screenshot(filepath)
            
            return filename
            
        except Exception as e:
            print(f"Error taking screenshot for {url}: {e}")
            return None
    
    def take_screenshot_with_payload(self, url: str, vulnerability_type: str, vuln_id: str, payload: str) -> Optional[str]:
        """
        Take screenshot showing payload execution
        Returns: screenshot filename or None if failed
        """
        try:
            self._init_driver()
            if self.driver is None:
                return None
            
            # Generate filename
            timestamp = int(time.time())
            filename = f"{vulnerability_type}_{vuln_id}_payload_{timestamp}.png"
            filepath = os.path.join(self.screenshots_dir, filename)
            
            # Navigate to URL
            self.driver.get(url)
            
            # Wait for page to load
            time.sleep(3)
            
            # For XSS, check if alert is present
            if vulnerability_type.lower() == 'xss':
                try:
                    from selenium.webdriver.support.ui import WebDriverWait
                    from selenium.webdriver.support import expected_conditions as EC
                    
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert.accept()  # Close alert before screenshot
                except:
                    pass  # No alert present
            
            # Take screenshot
            self.driver.save_screenshot(filepath)
            
            return filename
            
        except Exception as e:
            print(f"Error taking payload screenshot for {url}: {e}")
            return None
    
    def screenshot_to_base64(self, filename: str) -> Optional[str]:
        """Convert screenshot to base64 for embedding in HTML"""
        try:
            filepath = os.path.join(self.screenshots_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, "rb") as img_file:
                    return base64.b64encode(img_file.read()).decode('utf-8')
            return None
        except Exception as e:
            print(f"Error converting screenshot to base64: {e}")
            return None
    
    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
    
    def __del__(self):
        """Destructor to cleanup driver"""
        self.cleanup()
