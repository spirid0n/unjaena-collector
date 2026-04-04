"""
Legal Consent Dialog

Dialog for obtaining legal consent before starting collection.
Collection cannot proceed without consent.

2026-01 Server API Integration:
- GET /api/v1/collector/consent - Retrieve multilingual consent template
- POST /api/v1/collector/consent/accept - Save consent record
"""
from datetime import datetime, timezone
from typing import Optional, List
import socket
import hashlib
import requests
import logging

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QCheckBox,
    QPushButton, QTextEdit, QFrame, QScrollArea, QWidget,
    QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt

from gui.styles import COLORS

logger = logging.getLogger(__name__)


class ConsentDialog(QDialog):
    """Legal consent dialog (with server API integration)"""

    # Supported languages list
    LANGUAGES = {
        "en": "English",
        "ko": "한국어",
        "ja": "日本語",
        "zh": "中文"
    }

    def __init__(
        self,
        parent=None,
        server_url: str = None,
        session_id: str = None,
        case_id: str = None,
        language: str = "en"
    ):
        """
        Args:
            parent: Parent widget
            server_url: API server URL (e.g., http://localhost:8000)
            session_id: Collection session ID
            case_id: Case ID
            language: Default language code (en, ko, ja, zh)
        """
        super().__init__(parent)
        self.server_url = server_url
        self.session_id = session_id
        self.case_id = case_id
        self.language = language
        self.consent_given = False
        self.consent_record = None

        # Template information received from server
        self.template_id = None
        self.template_version = None
        self.template_content = None
        self.required_checkboxes: List[str] = []
        self.checkboxes: List[QCheckBox] = []

        self.setup_ui()

    def setup_ui(self):
        """Initialize UI (with server API integration)"""
        self.setWindowTitle("AI Forensic Lab - Data Collection Consent")
        self.setMinimumSize(700, 620)
        self.setMaximumSize(800, 720)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header + language selection
        header_layout = QHBoxLayout()

        self.header_label = QLabel("AI Forensic Lab - Data Collection Consent")
        self.header_label.setObjectName("header")
        header_layout.addWidget(self.header_label)

        header_layout.addStretch()

        # Language selection dropdown
        lang_label = QLabel("Language:")
        lang_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        header_layout.addWidget(lang_label)

        self.lang_combo = QComboBox()
        self.lang_combo.setMinimumWidth(100)
        for code, name in self.LANGUAGES.items():
            self.lang_combo.addItem(name, code)
        # Select current language
        idx = self.lang_combo.findData(self.language)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        header_layout.addWidget(self.lang_combo)

        layout.addLayout(header_layout)

        # Warning banner
        self.warning_frame = QFrame()
        self.warning_frame.setObjectName("warningFrame")
        warning_layout = QHBoxLayout(self.warning_frame)
        self.warning_label = QLabel(
            "Warning: This tool collects analysis data from your system.\n"
            "Please read and agree to the terms below before proceeding."
        )
        self.warning_label.setObjectName("warningText")
        warning_layout.addWidget(self.warning_label)
        layout.addWidget(self.warning_frame)

        # Scroll area (consent content)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(12)

        # Display consent content
        self.consent_text = QTextEdit()
        self.consent_text.setReadOnly(True)
        self.consent_text.setMinimumHeight(280)
        self.consent_text.setMaximumHeight(380)
        content_layout.addWidget(self.consent_text)

        scroll.setWidget(content_widget)
        layout.addWidget(scroll)

        # Checkbox area (dynamically generated from server items)
        self.checkbox_frame = QFrame()
        self.checkbox_frame.setObjectName("checkboxFrame")
        self.checkbox_layout = QVBoxLayout(self.checkbox_frame)
        self.checkbox_layout.setContentsMargins(8, 8, 8, 8)
        self.checkbox_layout.setSpacing(4)

        layout.addWidget(self.checkbox_frame)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(100)
        button_layout.addWidget(self.cancel_btn)

        self.agree_btn = QPushButton("Agree and Start Collection")
        self.agree_btn.setObjectName("agreeButton")
        self.agree_btn.setEnabled(False)
        self.agree_btn.clicked.connect(self._on_agree)
        self.agree_btn.setMinimumWidth(180)
        button_layout.addWidget(self.agree_btn)

        layout.addLayout(button_layout)

        # Load consent template from server
        self._load_consent_template()

    def _on_language_changed(self, index: int):
        """Reload consent when language changes"""
        self.language = self.lang_combo.currentData()
        self._load_consent_template()

    def _load_consent_template(self):
        """Load consent template from server"""
        # Remove existing checkboxes
        for cb in self.checkboxes:
            cb.deleteLater()
        self.checkboxes.clear()

        if self.server_url:
            try:
                template = self._fetch_consent_from_server()
                if template:
                    self._apply_template(template)
                    return
            except Exception as e:
                logger.warning(f"Failed to fetch consent from server: {e}")

        # Use default fallback when server connection fails
        self._apply_fallback_template()

    def _fetch_consent_from_server(self) -> Optional[dict]:
        """Fetch consent template from server"""
        try:
            url = f"{self.server_url}/api/v1/collector/consent"
            params = {"language": self.language, "category": "collection"}

            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            logger.info(f"Loaded consent template: lang={data['language']}, version={data['version']}")
            return data

        except requests.RequestException as e:
            logger.error(f"Failed to fetch consent template: {e}")
            return None

    def _apply_template(self, template: dict):
        """Apply server template"""
        self.template_id = template.get("id")
        self.template_version = template.get("version")
        self.template_content = template.get("content", "")
        self.required_checkboxes = template.get("required_checkboxes", [])

        # Update header
        self.header_label.setText(template.get("title", "AI Forensic Lab - Data Collection Consent"))
        self.setWindowTitle(template.get("title", "Consent"))

        # Display consent content (Markdown to HTML)
        content = template.get("content", "")
        html_content = self._markdown_to_html(content)
        self.consent_text.setHtml(html_content)

        # Generate dynamic checkboxes
        for item in self.required_checkboxes:
            cb = QCheckBox(item)
            cb.setObjectName("consentCheck")
            cb.stateChanged.connect(self._update_button_state)
            self.checkbox_layout.addWidget(cb)
            self.checkboxes.append(cb)

        # Button text (by language)
        btn_texts = {
            "ko": ("취소", "동의 후 수집 시작"),
            "ja": ("キャンセル", "同意して収集を開始"),
            "zh": ("取消", "同意并开始收集"),
            "en": ("Cancel", "Agree and Start Collection")
        }
        cancel_text, agree_text = btn_texts.get(self.language, btn_texts["en"])
        self.cancel_btn.setText(cancel_text)
        self.agree_btn.setText(agree_text)

        # Warning text (by language)
        warning_texts = {
            "ko": "경고: 이 도구는 시스템에서 분석 데이터를 수집합니다.\n아래 내용을 읽고 동의한 후 진행하세요.",
            "ja": "警告：このツールはシステムから分析データを収集します。\n以下の内容をお読みになり、同意の上お進みください。",
            "zh": "警告：此工具将从您的系统中收集分析数据。\n请阅读以下内容并同意后再继续。",
            "en": "Warning: This tool collects analysis data from your system.\nPlease read and agree to the terms below before proceeding."
        }
        self.warning_label.setText(warning_texts.get(self.language, warning_texts["en"]))

        self._update_button_state()

    def _apply_fallback_template(self):
        """Minimal fallback when server is unreachable."""
        self.template_id = None
        self.template_version = None
        self.template_content = None

        fallback_msgs = {
            'ko': '동의서를 불러올 수 없습니다. 인터넷 연결이 필요합니다.',
            'en': 'Consent information could not be loaded. Internet connection is required.',
            'ja': '同意書を読み込めませんでした。インターネット接続が必要です。',
            'zh': '无法加载同意书。需要互联网连接。',
        }
        msg = fallback_msgs.get(self.language, fallback_msgs['en'])

        self.header_label.setText("AI Forensic Lab - Data Collection Consent")
        self.setWindowTitle("AI Forensic Lab - Data Collection Consent")
        self.consent_text.setHtml(
            f'<div style="text-align:center;padding:40px;color:#ff6b6b;font-size:14px;">{msg}</div>'
        )

        # Disable agree button -- user must connect to server
        self.agree_btn.setEnabled(False)
        self.agree_btn.setText("Agree and Start Collection")
        self.cancel_btn.setText("Cancel")

    def _markdown_to_html(self, markdown_text: str) -> str:
        """Markdown to HTML conversion (supports tables, horizontal rules)"""
        import re

        # Remove carriage returns
        html = markdown_text.replace('\r\n', '\n').replace('\r', '\n')

        # Table conversion
        def convert_table(match):
            lines = match.group(0).strip().split('\n')
            if len(lines) < 2:
                return match.group(0)

            table_html = f'<table style="width:100%; border-collapse:collapse; margin:8px 0; font-size:12px;">'

            for i, line in enumerate(lines):
                if '---' in line:  # Skip separator line
                    continue
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if not cells:
                    continue

                tag = 'th' if i == 0 else 'td'
                bg = f'background:{COLORS["bg_secondary"]};' if i == 0 else ''
                row = ''.join([
                    f'<{tag} style="border:1px solid {COLORS["border_subtle"]}; padding:6px; {bg}">{c}</{tag}>'
                    for c in cells
                ])
                table_html += f'<tr>{row}</tr>'

            table_html += '</table>'
            return table_html

        html = re.sub(r'(\|.+\|\n)+', convert_table, html)

        # Horizontal rule (---)
        html = re.sub(r'^---+$', f'<hr style="border:none; border-top:1px solid {COLORS["border_subtle"]}; margin:12px 0;">', html, flags=re.MULTILINE)

        # Header (displayed as number. title format)
        html = re.sub(
            r'^### (\d+)\. (.+)$',
            rf'<h4 style="color:{COLORS["brand_primary"]}; margin:12px 0 6px 0; font-size:13px; font-weight:600;">\1. \2</h4>',
            html, flags=re.MULTILINE
        )
        html = re.sub(
            r'^## (.+)$',
            rf'<h3 style="color:{COLORS["brand_primary"]}; margin:0 0 10px 0; padding-bottom:8px; border-bottom:2px solid {COLORS["brand_primary"]}; font-size:16px;">\1</h3>',
            html, flags=re.MULTILINE
        )

        # Bold text
        html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', html)

        # List items
        html = re.sub(r'^- (.+)$', r'<li style="margin:2px 0; padding-left:4px;">\1</li>', html, flags=re.MULTILINE)

        # Wrap consecutive li elements in ul
        html = re.sub(r'((?:<li[^>]*>.*?</li>\n?)+)', r'<ul style="margin:4px 0 8px 16px; padding:0;">\1</ul>', html)

        # Handle empty lines (paragraph separation)
        html = re.sub(r'\n\n+', '</p><p style="margin:8px 0;">', html)
        html = re.sub(r'\n', ' ', html)  # Single line breaks become spaces

        # Version information style
        html = re.sub(
            r'\*\*버전\*\*: (v[\d.]+) \| \*\*시행일\*\*: ([\d-]+)',
            rf'<div style="margin-top:12px; padding:8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};">Version: \1 | Effective: \2</div>',
            html
        )
        html = re.sub(
            r'\*\*Version\*\*: (v[\d.]+) \| \*\*Effective\*\*: ([\d-]+)',
            rf'<div style="margin-top:12px; padding:8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};">Version: \1 | Effective: \2</div>',
            html
        )

        return f'''<div style="font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; line-height:1.5; color:{COLORS["text_primary"]}; font-size:12px;"><p style="margin:0;">{html}</p></div>'''

    def _submit_consent_to_server(self) -> bool:
        """Submit consent record to server"""
        if not self.server_url or not self.session_id:
            logger.warning("Server URL or session_id not set, skipping server submission")
            return True  # Continue even without server

        try:
            url = f"{self.server_url}/api/v1/collector/consent/accept"

            # List of agreed items
            agreed_items = [cb.text() for cb in self.checkboxes if cb.isChecked()]

            # System information
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "unknown"

            payload = {
                "session_id": self.session_id,
                "case_id": self.case_id or "",
                "template_id": self.template_id or "",
                "consent_version": self.template_version or "offline-1.0",
                "consent_language": self.language,
                "agreed_items": agreed_items,
                "collector_name": None,
                "collector_organization": None,
                "target_system_info": {"hostname": hostname},
                "signature_type": "checkbox"
            }

            headers = {"Content-Type": "application/json"}

            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()

            result = response.json()
            logger.info(f"Consent submitted: consent_id={result.get('consent_id')}")
            return True

        except requests.RequestException as e:
            logger.error(f"Failed to submit consent to server: {e}")
            # Keep local record even if server submission fails
            return True

    # Consent text methods removed -- consent content is fetched from server.
    # See _load_consent_template() and _fetch_consent_from_server().

    def _update_button_state(self):
        """Enable button based on checkbox state (all checkboxes must be checked)"""
        all_checked = all(cb.isChecked() for cb in self.checkboxes) if self.checkboxes else False
        self.agree_btn.setEnabled(all_checked)

    def _on_agree(self):
        """Agree button clicked"""
        # Submit consent record to server
        self._submit_consent_to_server()

        self.consent_given = True
        self.consent_record = self._create_consent_record()
        self.accept()

    def _create_consent_record(self) -> dict:
        """Create consent record (server API integration version)"""
        import hmac
        import os

        timestamp = datetime.now(timezone.utc).isoformat()

        # System information
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip_address = "unknown"

        # [Security] Privacy protection: Hash IP address and hostname
        hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()[:16]
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]

        # List of agreed items (from dynamic checkboxes)
        agreed_items = [cb.text() for cb in self.checkboxes if cb.isChecked()]

        record = {
            "consent_timestamp": timestamp,
            "consent_version": self.template_version or "offline-1.0",
            "consent_language": self.language,
            "template_id": self.template_id,
            "hostname_hash": hostname_hash,
            "ip_hash": ip_hash,
            "session_id": self.session_id,
            "case_id": self.case_id,
            "agreed_items": agreed_items,
            "legal_basis": {
                "pipa_article_15": "Collection and Use Consent",
                "pipa_article_17": "Third-party Provision Consent",
                "pipa_article_28_8": "Overseas Transfer Consent",
                "pipa_article_37_2": "Automated Decision-making Notice",
                "pipa_article_35_3": "Data Portability Right"
            }
        }

        # Consent record hash (integrity)
        items_str = "|".join(agreed_items)
        record_str = f"{timestamp}|{hostname_hash}|{ip_hash}|{items_str}"
        record["consent_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

        # HMAC signature
        signing_key = os.getenv("CONSENT_SIGNING_KEY")
        if not signing_key:
            # Fallback: random key (signature for local integrity only)
            signing_key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]

        verify_payload = f"{timestamp}|{record['consent_version']}|{record['consent_hash']}"
        record["server_verify_signature"] = hmac.new(
            signing_key.encode(),
            verify_payload.encode(),
            hashlib.sha256
        ).hexdigest()

        record["_verification"] = {
            "algorithm": "HMAC-SHA256",
            "signed_at": timestamp,
            "payload_fields": ["consent_timestamp", "consent_version", "consent_hash"]
        }

        return record

    def get_consent_record(self) -> Optional[dict]:
        """Return consent record"""
        return self.consent_record if self.consent_given else None

    def _get_stylesheet(self) -> str:
        """Stylesheet - platform unified theme"""
        return f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
            #header {{
                font-size: 20px;
                font-weight: bold;
                color: {COLORS['brand_primary']};
                padding: 8px;
            }}
            #warningFrame {{
                background-color: rgba(248, 81, 73, 0.15);
                border: 1px solid {COLORS['error']};
                border-radius: 8px;
                padding: 12px;
            }}
            #warningText {{
                color: {COLORS['error']};
                font-size: 13px;
            }}
            #checkboxFrame {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                padding: 8px;
            }}
            #consentCheck {{
                color: {COLORS['text_primary']};
                background-color: transparent;
                font-size: 11px;
                spacing: 6px;
                padding: 2px 0;
            }}
            #consentCheck::indicator {{
                width: 16px;
                height: 16px;
                border: 2px solid {COLORS['border_subtle']};
                border-radius: 3px;
                background-color: {COLORS['bg_tertiary']};
            }}
            #consentCheck::indicator:checked {{
                background-color: {COLORS['brand_primary']};
                border-color: {COLORS['brand_primary']};
            }}
            QTextEdit {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 8px;
                color: {COLORS['text_primary']};
                padding: 12px;
                font-size: 13px;
            }}
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 6px;
                color: {COLORS['text_primary']};
                padding: 10px 20px;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['bg_hover']};
                border-color: {COLORS['border_default']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            #agreeButton {{
                background-color: {COLORS['brand_primary']};
                border: none;
                color: {COLORS['bg_primary']};
                font-weight: bold;
            }}
            #agreeButton:hover {{
                background-color: {COLORS['brand_accent']};
            }}
            #agreeButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_tertiary']};
            }}
            QScrollArea {{
                background-color: transparent;
            }}
        """


def show_consent_dialog(
    parent=None,
    server_url: str = None,
    session_id: str = None,
    case_id: str = None,
    language: str = "en"
) -> Optional[dict]:
    """
    Display consent dialog and return result

    Args:
        parent: Parent widget
        server_url: API server URL (e.g., http://localhost:8000)
        session_id: Collection session ID
        case_id: Case ID
        language: Default language code (en, ko, ja, zh)

    Returns:
        Consent record dict (if agreed) or None (if cancelled)
    """
    dialog = ConsentDialog(
        parent=parent,
        server_url=server_url,
        session_id=session_id,
        case_id=case_id,
        language=language
    )
    result = dialog.exec()

    if result == QDialog.DialogCode.Accepted:
        return dialog.get_consent_record()
    return None


if __name__ == "__main__":
    # For testing
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    # Server integration test
    record = show_consent_dialog(
        server_url="http://localhost:8000",
        session_id="test-session-123",
        case_id="test-case-456",
        language="ko"
    )

    if record:
        print("Consent accepted:", record)
    else:
        print("Consent rejected or cancelled")
