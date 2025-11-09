import unittest
import requests
import sys
import os

# Добавляем корневую директорию проекта в путь для импорта детектора
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detectors.openredirect_detector import OpenRedirectDetector

class TestOpenRedirectDetector(unittest.TestCase):
    """Тесты для OpenRedirectDetector"""

    def test_detect_open_redirect_on_xvwa(self):
        """
        Тестирование уязвимости open redirect на известном уязвимом URL.
        """
        base_url = "http://185.233.118.120:8082/xvwa/vulnerabilities/redirect/redirect.php"
        payload_url = "http://evil.com"
        test_url = f"{base_url}?forward={payload_url}"

        try:
            # Отключаем автоматические редиректы, чтобы поймать заголовок Location
            response = requests.get(test_url, allow_redirects=False, timeout=10)
            
            is_vulnerable, details, redirect_type = OpenRedirectDetector.detect_open_redirect(
                response_text=response.text,
                response_code=response.status_code,
                response_headers=response.headers,
                payload_url=payload_url,
                original_url=base_url
            )

            print(f"\n--- Результаты теста Open Redirect ---")
            print(f"URL для теста: {test_url}")
            print(f"Уязвимость найдена: {is_vulnerable}")
            print(f"Детали: {details}")
            print(f"Тип редиректа: {redirect_type}")
            print(f"------------------------------------")

            self.assertTrue(is_vulnerable, "Уязвимость open redirect не была обнаружена.")
            self.assertEqual("redirect_header", redirect_type, "Обнаружен неверный тип редиректа.")
            self.assertIn(payload_url, details.lower(), "URL полезной нагрузки не найден в деталях обнаружения.")

        except requests.exceptions.RequestException as e:
            self.fail(f"Запрос на тестовый URL не удался: {e}")

if __name__ == '__main__':
    unittest.main()
