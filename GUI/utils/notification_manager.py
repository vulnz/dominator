#!/usr/bin/env python3
"""
Notification Manager for Dominator GUI
Sends scan results via Telegram, Email, or Slack
"""

import json
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Settings file path
SETTINGS_FILE = Path(__file__).parent.parent.parent / "settings.json"


class NotificationManager:
    """Manages notifications for scan results"""

    _instance = None

    @classmethod
    def get_instance(cls):
        """Get or create singleton instance"""
        if cls._instance is None:
            cls._instance = NotificationManager()
        return cls._instance

    def __init__(self):
        self.settings = self._load_settings()

    def _load_settings(self):
        """Load notification settings from file"""
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('notifications', {})
        except Exception as e:
            print(f"Error loading notification settings: {e}")
        return {}

    def save_settings(self, settings):
        """Save notification settings to file"""
        try:
            data = {}
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)

            data['notifications'] = settings
            self.settings = settings

            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving notification settings: {e}")
            return False

    def send_notification(self, title, message, results_summary=None):
        """Send notification through enabled channels"""
        results = []

        # Telegram
        if self.settings.get('telegram_enabled'):
            success, msg = self.send_telegram(title, message, results_summary)
            results.append(('Telegram', success, msg))

        # Email
        if self.settings.get('email_enabled'):
            success, msg = self.send_email(title, message, results_summary)
            results.append(('Email', success, msg))

        # Slack
        if self.settings.get('slack_enabled'):
            success, msg = self.send_slack(title, message, results_summary)
            results.append(('Slack', success, msg))

        return results

    def send_telegram(self, title, message, results_summary=None):
        """Send notification via Telegram Bot"""
        if not HAS_REQUESTS:
            return False, "requests library not installed"

        bot_token = self.settings.get('telegram_bot_token', '')
        chat_id = self.settings.get('telegram_chat_id', '')

        if not bot_token or not chat_id:
            return False, "Missing bot token or chat ID"

        try:
            # Format message for Telegram
            text = f"*{title}*\n\n{message}"

            if results_summary:
                text += "\n\n*Summary:*\n"
                text += f"• Critical: {results_summary.get('critical', 0)}\n"
                text += f"• High: {results_summary.get('high', 0)}\n"
                text += f"• Medium: {results_summary.get('medium', 0)}\n"
                text += f"• Low: {results_summary.get('low', 0)}\n"
                text += f"• Total: {results_summary.get('total', 0)}"

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': text,
                'parse_mode': 'Markdown'
            }

            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                return True, "Sent successfully"
            else:
                return False, f"API error: {response.text}"

        except Exception as e:
            return False, str(e)

    def send_email(self, title, message, results_summary=None):
        """Send notification via Email (SMTP)"""
        smtp_server = self.settings.get('email_smtp_server', '')
        smtp_port = self.settings.get('email_smtp_port', 587)
        username = self.settings.get('email_username', '')
        password = self.settings.get('email_password', '')
        from_email = self.settings.get('email_from', '')
        to_email = self.settings.get('email_to', '')

        if not all([smtp_server, username, password, to_email]):
            return False, "Missing email configuration"

        if not from_email:
            from_email = username

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[Dominator] {title}"
            msg['From'] = from_email
            msg['To'] = to_email

            # Plain text version
            text_content = f"{title}\n\n{message}"

            if results_summary:
                text_content += "\n\nSummary:\n"
                text_content += f"- Critical: {results_summary.get('critical', 0)}\n"
                text_content += f"- High: {results_summary.get('high', 0)}\n"
                text_content += f"- Medium: {results_summary.get('medium', 0)}\n"
                text_content += f"- Low: {results_summary.get('low', 0)}\n"
                text_content += f"- Total: {results_summary.get('total', 0)}"

            # HTML version
            html_content = f"""
            <html>
            <body>
                <h2 style="color: #4CAF50;">{title}</h2>
                <p>{message}</p>
            """

            if results_summary:
                html_content += """
                <h3>Summary</h3>
                <table style="border-collapse: collapse;">
                    <tr>
                        <td style="padding: 5px; color: #f44336;"><strong>Critical:</strong></td>
                        <td style="padding: 5px;">{critical}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; color: #FF9800;"><strong>High:</strong></td>
                        <td style="padding: 5px;">{high}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; color: #FFC107;"><strong>Medium:</strong></td>
                        <td style="padding: 5px;">{medium}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; color: #4CAF50;"><strong>Low:</strong></td>
                        <td style="padding: 5px;">{low}</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px;"><strong>Total:</strong></td>
                        <td style="padding: 5px;">{total}</td>
                    </tr>
                </table>
                """.format(**results_summary)

            html_content += """
                <p style="color: #888; font-size: 12px; margin-top: 20px;">
                    Sent by Dominator Web Vulnerability Scanner
                </p>
            </body>
            </html>
            """

            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))

            # Send email
            context = ssl.create_default_context()

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                server.login(username, password)
                server.sendmail(from_email, to_email, msg.as_string())

            return True, "Sent successfully"

        except Exception as e:
            return False, str(e)

    def send_slack(self, title, message, results_summary=None):
        """Send notification via Slack Webhook"""
        if not HAS_REQUESTS:
            return False, "requests library not installed"

        webhook_url = self.settings.get('slack_webhook_url', '')

        if not webhook_url:
            return False, "Missing Slack webhook URL"

        try:
            # Build Slack message blocks
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔒 {title}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message
                    }
                }
            ]

            if results_summary:
                fields = [
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical:* {results_summary.get('critical', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*High:* {results_summary.get('high', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Medium:* {results_summary.get('medium', 0)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Low:* {results_summary.get('low', 0)}"
                    }
                ]

                blocks.append({
                    "type": "section",
                    "fields": fields
                })

                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Total vulnerabilities: *{results_summary.get('total', 0)}*"
                        }
                    ]
                })

            payload = {
                "blocks": blocks
            }

            response = requests.post(webhook_url, json=payload, timeout=10)

            if response.status_code == 200:
                return True, "Sent successfully"
            else:
                return False, f"Webhook error: {response.text}"

        except Exception as e:
            return False, str(e)

    def test_telegram(self):
        """Test Telegram connection"""
        return self.send_telegram(
            "Test Notification",
            "This is a test message from Dominator.",
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'total': 6}
        )

    def test_email(self):
        """Test Email connection"""
        return self.send_email(
            "Test Notification",
            "This is a test message from Dominator.",
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'total': 6}
        )

    def test_slack(self):
        """Test Slack connection"""
        return self.send_slack(
            "Test Notification",
            "This is a test message from Dominator.",
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'total': 6}
        )


def get_notification_manager():
    """Get the global notification manager instance"""
    return NotificationManager.get_instance()
