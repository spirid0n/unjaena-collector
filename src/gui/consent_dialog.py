"""
Legal Consent Dialog

수집 시작 전 법적 동의를 받는 다이얼로그.
동의 없이는 수집 진행 불가.

2026-01 서버 API 연동:
- GET /api/v1/collector/consent - 다국어 동의서 템플릿 조회
- POST /api/v1/collector/consent/accept - 동의 기록 저장
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
from PyQt6.QtGui import QFont

from gui.styles import COLORS

logger = logging.getLogger(__name__)


class ConsentDialog(QDialog):
    """법적 동의 다이얼로그 (서버 API 연동)"""

    # 지원 언어 목록
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
            parent: 부모 위젯
            server_url: API 서버 URL (예: http://localhost:8000)
            session_id: 수집 세션 ID
            case_id: 케이스 ID
            language: 기본 언어 코드 (en, ko, ja, zh)
        """
        super().__init__(parent)
        self.server_url = server_url
        self.session_id = session_id
        self.case_id = case_id
        self.language = language
        self.consent_given = False
        self.consent_record = None

        # 서버에서 받은 템플릿 정보
        self.template_id = None
        self.template_version = None
        self.template_content = None
        self.required_checkboxes: List[str] = []
        self.checkboxes: List[QCheckBox] = []

        self.setup_ui()

    def setup_ui(self):
        """UI 초기화 (서버 API 연동)"""
        self.setWindowTitle("Digital Forensic Collection Consent")
        self.setMinimumSize(700, 620)
        self.setMaximumSize(800, 720)
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 16, 16, 16)

        # 헤더 + 언어 선택
        header_layout = QHBoxLayout()

        self.header_label = QLabel("Digital Forensic Collection Consent")
        self.header_label.setObjectName("header")
        header_layout.addWidget(self.header_label)

        header_layout.addStretch()

        # 언어 선택 드롭다운
        lang_label = QLabel("Language:")
        lang_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        header_layout.addWidget(lang_label)

        self.lang_combo = QComboBox()
        self.lang_combo.setMinimumWidth(100)
        for code, name in self.LANGUAGES.items():
            self.lang_combo.addItem(name, code)
        # 현재 언어 선택
        idx = self.lang_combo.findData(self.language)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        header_layout.addWidget(self.lang_combo)

        layout.addLayout(header_layout)

        # 경고 배너
        self.warning_frame = QFrame()
        self.warning_frame.setObjectName("warningFrame")
        warning_layout = QHBoxLayout(self.warning_frame)
        self.warning_label = QLabel(
            "Warning: This tool collects forensic data from your system.\n"
            "Please read and agree to the terms below before proceeding."
        )
        self.warning_label.setObjectName("warningText")
        warning_layout.addWidget(self.warning_label)
        layout.addWidget(self.warning_frame)

        # 스크롤 영역 (동의서 내용)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(12)

        # 동의서 내용 표시
        self.consent_text = QTextEdit()
        self.consent_text.setReadOnly(True)
        self.consent_text.setMinimumHeight(280)
        self.consent_text.setMaximumHeight(380)
        content_layout.addWidget(self.consent_text)

        scroll.setWidget(content_widget)
        layout.addWidget(scroll)

        # 체크박스 영역 (서버에서 받은 항목으로 동적 생성)
        self.checkbox_frame = QFrame()
        self.checkbox_frame.setObjectName("checkboxFrame")
        self.checkbox_layout = QVBoxLayout(self.checkbox_frame)
        self.checkbox_layout.setContentsMargins(8, 8, 8, 8)
        self.checkbox_layout.setSpacing(4)

        layout.addWidget(self.checkbox_frame)

        # 버튼
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

        # 서버에서 동의서 템플릿 로드
        self._load_consent_template()

    def _on_language_changed(self, index: int):
        """언어 변경 시 동의서 다시 로드"""
        self.language = self.lang_combo.currentData()
        self._load_consent_template()

    def _load_consent_template(self):
        """서버에서 동의서 템플릿 로드"""
        # 기존 체크박스 제거
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

        # 서버 연결 실패 시 기본 폴백 사용
        self._apply_fallback_template()

    def _fetch_consent_from_server(self) -> Optional[dict]:
        """서버에서 동의서 템플릿 가져오기"""
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
        """서버 템플릿 적용"""
        self.template_id = template.get("id")
        self.template_version = template.get("version")
        self.template_content = template.get("content", "")
        self.required_checkboxes = template.get("required_checkboxes", [])

        # 헤더 업데이트
        self.header_label.setText(template.get("title", "Digital Forensic Collection Consent"))
        self.setWindowTitle(template.get("title", "Consent"))

        # 동의서 내용 표시 (Markdown to HTML)
        content = template.get("content", "")
        html_content = self._markdown_to_html(content)
        self.consent_text.setHtml(html_content)

        # 동적 체크박스 생성
        for item in self.required_checkboxes:
            cb = QCheckBox(item)
            cb.setObjectName("consentCheck")
            cb.stateChanged.connect(self._update_button_state)
            self.checkbox_layout.addWidget(cb)
            self.checkboxes.append(cb)

        # 버튼 텍스트 (언어별)
        btn_texts = {
            "ko": ("취소", "동의 및 수집 시작"),
            "ja": ("キャンセル", "同意して収集開始"),
            "zh": ("取消", "同意并开始收集"),
            "en": ("Cancel", "Agree and Start Collection")
        }
        cancel_text, agree_text = btn_texts.get(self.language, btn_texts["en"])
        self.cancel_btn.setText(cancel_text)
        self.agree_btn.setText(agree_text)

        # 경고 텍스트 (언어별)
        warning_texts = {
            "ko": "경고: 본 도구는 시스템에서 포렌식 데이터를 수집합니다.\n반드시 아래 내용을 숙지하고 동의 후 진행하시기 바랍니다.",
            "ja": "警告: このツールはシステムからフォレンジックデータを収集します。\n以下の内容を確認し、同意してから進めてください。",
            "zh": "警告：本工具将从您的系统收集取证数据。\n请仔细阅读以下内容并同意后再继续。",
            "en": "Warning: This tool collects forensic data from your system.\nPlease read and agree to the terms below before proceeding."
        }
        self.warning_label.setText(warning_texts.get(self.language, warning_texts["en"]))

        self._update_button_state()

    def _apply_fallback_template(self):
        """오프라인 폴백 템플릿 적용"""
        self.template_id = None
        self.template_version = "offline-1.0"
        self.template_content = self._get_consent_html()

        self.header_label.setText("Digital Forensic Collection Consent")
        self.consent_text.setHtml(self.template_content)

        # 기본 체크박스
        default_items = [
            "I have read and understood the collection scope",
            "I authorize the collection of specified artifacts",
            "I confirm I have authority to provide this consent"
        ]

        for item in default_items:
            cb = QCheckBox(item)
            cb.setObjectName("consentCheck")
            cb.stateChanged.connect(self._update_button_state)
            self.checkbox_layout.addWidget(cb)
            self.checkboxes.append(cb)
            self.required_checkboxes.append(item)

        self._update_button_state()

    def _markdown_to_html(self, markdown_text: str) -> str:
        """Markdown to HTML 변환 (테이블, 구분선 지원)"""
        import re

        # 캐리지 리턴 제거
        html = markdown_text.replace('\r\n', '\n').replace('\r', '\n')

        # 테이블 변환
        def convert_table(match):
            lines = match.group(0).strip().split('\n')
            if len(lines) < 2:
                return match.group(0)

            table_html = f'<table style="width:100%; border-collapse:collapse; margin:8px 0; font-size:12px;">'

            for i, line in enumerate(lines):
                if '---' in line:  # 구분선 스킵
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

        # 구분선 (---)
        html = re.sub(r'^---+$', f'<hr style="border:none; border-top:1px solid {COLORS["border_subtle"]}; margin:12px 0;">', html, flags=re.MULTILINE)

        # 헤더 (숫자. 제목 형태로 표시)
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

        # Bold
        html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', html)

        # 리스트 아이템
        html = re.sub(r'^- (.+)$', r'<li style="margin:2px 0; padding-left:4px;">\1</li>', html, flags=re.MULTILINE)

        # 연속된 li를 ul로 감싸기
        html = re.sub(r'((?:<li[^>]*>.*?</li>\n?)+)', r'<ul style="margin:4px 0 8px 16px; padding:0;">\1</ul>', html)

        # 빈 줄 처리 (단락 구분)
        html = re.sub(r'\n\n+', '</p><p style="margin:8px 0;">', html)
        html = re.sub(r'\n', ' ', html)  # 단일 줄바꿈은 공백으로

        # 버전 정보 스타일
        html = re.sub(
            r'\*\*버전\*\*: (v[\d.]+) \| \*\*시행일\*\*: ([\d-]+)',
            rf'<div style="margin-top:12px; padding:8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};">버전: \1 | 시행일: \2</div>',
            html
        )
        html = re.sub(
            r'\*\*Version\*\*: (v[\d.]+) \| \*\*Effective\*\*: ([\d-]+)',
            rf'<div style="margin-top:12px; padding:8px; background:{COLORS["bg_secondary"]}; border-radius:4px; font-size:11px; color:{COLORS["text_secondary"]};">Version: \1 | Effective: \2</div>',
            html
        )

        return f'''<div style="font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; line-height:1.5; color:{COLORS["text_primary"]}; font-size:12px;"><p style="margin:0;">{html}</p></div>'''

    def _submit_consent_to_server(self) -> bool:
        """서버에 동의 기록 제출"""
        if not self.server_url or not self.session_id:
            logger.warning("Server URL or session_id not set, skipping server submission")
            return True  # 서버 없이도 계속 진행

        try:
            url = f"{self.server_url}/api/v1/collector/consent/accept"

            # 동의한 항목 목록
            agreed_items = [cb.text() for cb in self.checkboxes if cb.isChecked()]

            # 시스템 정보
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
            # 서버 제출 실패해도 로컬 기록은 유지
            return True

    def _get_consent_html(self) -> str:
        """동의서 HTML 내용 (개인정보 보호법 준수)"""
        return f"""
        <div style="font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; line-height: 1.8; color: {COLORS['text_primary']};">

        <!-- ===== 1. 개인정보 수집·이용 동의 ===== -->
        <h3 style="color: {COLORS['brand_primary']}; border-bottom: 2px solid {COLORS['brand_primary']}; padding-bottom: 8px;">
            1. 개인정보 수집·이용 동의
        </h3>
        <table style="width: 100%; border-collapse: collapse; margin: 12px 0;">
            <tr style="background: {COLORS['bg_secondary']};">
                <th style="border: 1px solid {COLORS['border_subtle']}; padding: 10px; width: 25%;">항목</th>
                <th style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">내용</th>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px; font-weight: bold;">수집 목적</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    디지털 포렌식 분석, 보안 사고 조사, 법적 증거 확보, AI 기반 이상 징후 탐지
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px; font-weight: bold;">수집 항목</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    <b>[시스템]</b> Prefetch, Amcache, UserAssist, 이벤트 로그(Security, System, Application),
                    레지스트리(SYSTEM, SOFTWARE, SAM, NTUSER.DAT), MFT, USN Journal, $LogFile<br>
                    <b>[사용자 활동]</b> 브라우저 기록, USB 연결 이력, 휴지통, 바로가기, 점프목록<br>
                    <b>[문서/이메일]</b> Office 문서(doc/docx/xls/xlsx/ppt/pptx), PDF, 한글(hwp/hwpx), 이메일(pst/ost/eml/msg)
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px; font-weight: bold;">보유 기간</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    케이스 종료 후 <b>30일</b> (보유 기간 만료 시 자동 파기)<br>
                    ※ 보관 기간은 케이스 상세 페이지에서 크레딧을 사용하여 연장 가능
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px; font-weight: bold;">처리 방식</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    • SHA-256 해시를 통한 무결성 검증<br>
                    • TLS 1.3 암호화 통신<br>
                    • AES-256-GCM 암호화 저장<br>
                    • Chain of Custody 기록
                </td>
            </tr>
        </table>

        <!-- ===== 2. 개인정보 국외이전 고지 ===== -->
        <h3 style="color: {COLORS['warning']}; border-bottom: 2px solid {COLORS['warning']}; padding-bottom: 8px;">
            2. 개인정보 국외이전 고지
        </h3>
        <p style="background: rgba(210, 153, 34, 0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['warning']};">
            <b>알림:</b> 수집된 데이터는 클라우드 서버에 저장되며, 서버 위치에 따라 국외로 이전될 수 있습니다.
            개인정보 보호법 제28조의8에 따라 아래 사항을 고지합니다.
        </p>
        <table style="width: 100%; border-collapse: collapse; margin: 12px 0;">
            <tr style="background: {COLORS['bg_secondary']};">
                <th style="border: 1px solid {COLORS['border_subtle']}; padding: 10px; width: 30%;">항목</th>
                <th style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">내용</th>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">이전받는 자</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    RunPod, Inc. (GPU 서버) / Cloudflare, Inc. (R2 스토리지, CDN)
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">이전 국가</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    아시아태평양 (서울, 일본) - 서버 가용성에 따라 변동 가능
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">이전 일시 및 방법</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    수집 즉시 TLS 암호화 통신으로 실시간 전송
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">이전 목적</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    암호화된 데이터 저장, AI 분석 처리, 분석 결과 제공
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">보유 및 이용 기간</td>
                <td style="border: 1px solid {COLORS['border_subtle']}; padding: 10px;">
                    케이스 종료 후 30일 (연장 가능)
                </td>
            </tr>
        </table>

        <!-- ===== 3. AI 분석 및 자동화된 의사결정 고지 ===== -->
        <h3 style="color: {COLORS['brand_accent']}; border-bottom: 2px solid {COLORS['brand_accent']}; padding-bottom: 8px;">
            3. AI 분석 및 자동화된 의사결정 고지
        </h3>
        <p style="background: rgba(212, 165, 116, 0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['brand_accent']};">
            <b>AI 기본법 및 개인정보 보호법 제37조의2에 따른 고지</b>
        </p>
        <ul>
            <li><b>AI 활용 사실:</b> 본 서비스는 인공지능(AI)을 활용하여 수집된 데이터를 자동으로 분석합니다.
                분석에는 패턴 인식, 이상 징후 탐지, 연관성 분석, 자동 리포트 생성이 포함됩니다.</li>
            <li><b>자동화된 의사결정:</b> AI가 "의심스러운 활동", "악성코드 징후" 등을 자동으로 판단하며,
                이러한 판단은 <u>참고 목적</u>으로만 제공됩니다.</li>
            <li><b>AI 분석의 한계:</b>
                <ul>
                    <li>AI는 학습 데이터에 기반한 패턴 인식 결과를 제공하며, 100% 정확성을 보장하지 않습니다.</li>
                    <li>오탐(False Positive) 또는 미탐(False Negative)이 발생할 수 있습니다.</li>
                    <li>AI 환각(Hallucination)으로 인해 존재하지 않는 정보가 생성될 수 있습니다.</li>
                </ul>
            </li>
            <li style="color: {COLORS['error']};"><b>법적 분쟁 가능성:</b>
                AI 분석 결과를 근거로 법적 조치(고소, 징계, 해고 등)를 취할 경우,
                분석 결과의 정확성에 대한 법적 분쟁이 발생할 수 있으며,
                <u>귀하가 법적 소송의 당사자가 될 수 있습니다.</u>
                반드시 전문가(포렌식 전문가, 법률 전문가) 검토 후 사용하십시오.
            </li>
            <li><b>정보주체 권리:</b> 개인정보 보호법 제37조의2에 따라 자동화된 결정에 대해
                거부권, 설명요구권, 인적 개입 요구권을 행사할 수 있습니다.</li>
        </ul>

        <!-- ===== 4. 정보주체 권리 안내 ===== -->
        <h3 style="color: {COLORS['success']}; border-bottom: 2px solid {COLORS['success']}; padding-bottom: 8px;">
            4. 정보주체 권리 안내
        </h3>
        <p>귀하는 개인정보 보호법에 따라 다음의 권리를 행사할 수 있습니다:</p>
        <ul>
            <li><b>열람권:</b> 수집된 개인정보의 열람을 요청할 수 있습니다.</li>
            <li><b>정정권:</b> 부정확한 정보의 정정을 요청할 수 있습니다.</li>
            <li><b>삭제권:</b> 개인정보의 삭제를 요청할 수 있습니다 (단, 법적 보존 의무 기간 내 제외).</li>
            <li><b>처리정지권:</b> 개인정보 처리의 정지를 요청할 수 있습니다.</li>
            <li><b>동의철회권:</b> 언제든지 동의를 철회할 수 있습니다 (이미 처리된 데이터 제외).</li>
        </ul>
        <p>권리 행사: 서비스 관리자 또는 support@forensics-ai.com으로 문의</p>

        <!-- ===== 5. 법적 경고 및 면책 ===== -->
        <h3 style="color: {COLORS['error']}; border-bottom: 2px solid {COLORS['error']}; padding-bottom: 8px;">
            5. 법적 경고 및 면책
        </h3>
        <p style="background: rgba(248, 81, 73, 0.15); padding: 12px; border-radius: 8px; border-left: 4px solid {COLORS['error']};">
            <b>경고:</b> 타인의 시스템에서 권한 없이 데이터를 수집하는 행위는
            「정보통신망 이용촉진 및 정보보호 등에 관한 법률」,
            「형법」(컴퓨터 등 사용 사기), 「개인정보 보호법」 등에 의해
            <u>5년 이하의 징역 또는 5천만원 이하의 벌금</u>에 처해질 수 있습니다.
        </p>
        <ul>
            <li>반드시 <b>시스템 소유자의 서면 동의</b> 또는 <b>법적 권한</b>(수사기관 영장 등)이 있는 경우에만 사용하십시오.</li>
            <li>기업 내부 조사 시 <b>법무팀 사전 검토</b> 및 <b>노동법 준수</b>를 확인하십시오.</li>
        </ul>
        <p style="background: rgba(100, 100, 100, 0.2); padding: 12px; border-radius: 8px; margin-top: 12px;">
            <b>면책 조항:</b><br>
            • 회사는 AI 분석 결과의 오류, 누락, 오해석으로 인한 손해에 대해 책임을 지지 않습니다.<br>
            • 무단 수집으로 인한 모든 법적 책임은 사용자에게 있습니다.<br>
            • AI 분석 결과를 법적 증거로 사용 시 발생하는 분쟁에 대해 회사는 책임을 지지 않습니다.
        </p>

        </div>
        """

    def _update_button_state(self):
        """체크박스 상태에 따라 버튼 활성화 (모든 체크박스 체크 필요)"""
        all_checked = all(cb.isChecked() for cb in self.checkboxes) if self.checkboxes else False
        self.agree_btn.setEnabled(all_checked)

    def _on_agree(self):
        """동의 버튼 클릭"""
        # 서버에 동의 기록 제출
        self._submit_consent_to_server()

        self.consent_given = True
        self.consent_record = self._create_consent_record()
        self.accept()

    def _create_consent_record(self) -> dict:
        """동의 기록 생성 (서버 API 연동 버전)"""
        import hmac
        import os

        timestamp = datetime.now(timezone.utc).isoformat()

        # 시스템 정보
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip_address = "unknown"

        # [보안] 개인정보 보호: IP 주소와 호스트명을 해시 처리
        hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()[:16]
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]

        # 동의한 항목 목록 (동적 체크박스에서)
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
                "pipa_article_28_8": "Overseas Transfer Consent",
                "pipa_article_37_2": "Automated Decision-making Notice"
            }
        }

        # 동의 기록 해시 (무결성)
        items_str = "|".join(agreed_items)
        record_str = f"{timestamp}|{hostname_hash}|{ip_hash}|{items_str}"
        record["consent_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

        # HMAC 서명
        signing_key = os.getenv("CONSENT_SIGNING_KEY")
        if not signing_key:
            signing_key = hashlib.sha256(
                f"consent_sign_{self.session_id or 'default'}".encode()
            ).hexdigest()[:32]

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
        """동의 기록 반환"""
        return self.consent_record if self.consent_given else None

    def _get_stylesheet(self) -> str:
        """스타일시트 - 플랫폼 통일 테마"""
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
    동의 다이얼로그 표시 및 결과 반환

    Args:
        parent: 부모 위젯
        server_url: API 서버 URL (예: http://localhost:8000)
        session_id: 수집 세션 ID
        case_id: 케이스 ID
        language: 기본 언어 코드 (en, ko, ja, zh)

    Returns:
        동의 기록 dict (동의한 경우) 또는 None (취소한 경우)
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
    # 테스트용
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    # 서버 연동 테스트
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
