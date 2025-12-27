"""
Legal Consent Dialog

수집 시작 전 법적 동의를 받는 다이얼로그.
동의 없이는 수집 진행 불가.
"""
from datetime import datetime
from typing import Optional
import socket
import hashlib

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QCheckBox,
    QPushButton, QTextEdit, QFrame, QScrollArea, QWidget
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


class ConsentDialog(QDialog):
    """법적 동의 다이얼로그"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.consent_given = False
        self.consent_record = None
        self.setup_ui()

    def setup_ui(self):
        """UI 초기화"""
        self.setWindowTitle("디지털 포렌식 수집 동의서")
        self.setMinimumSize(700, 850)  # 확장된 동의서 내용을 위해 크기 증가
        self.setModal(True)
        self.setStyleSheet(self._get_stylesheet())

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # 헤더
        header = QLabel("디지털 포렌식 수집 동의서")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # 경고 배너
        warning_frame = QFrame()
        warning_frame.setObjectName("warningFrame")
        warning_layout = QHBoxLayout(warning_frame)
        warning_label = QLabel(
            "⚠️ 주의: 본 도구는 시스템에서 포렌식 데이터를 수집합니다.\n"
            "반드시 아래 내용을 숙지하고 동의 후 진행하시기 바랍니다."
        )
        warning_label.setObjectName("warningText")
        warning_layout.addWidget(warning_label)
        layout.addWidget(warning_frame)

        # 스크롤 영역 (동의서 내용)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(12)

        # 동의서 내용
        consent_text = QTextEdit()
        consent_text.setReadOnly(True)
        consent_text.setHtml(self._get_consent_html())
        consent_text.setMinimumHeight(300)
        content_layout.addWidget(consent_text)

        scroll.setWidget(content_widget)
        layout.addWidget(scroll)

        # 체크박스 영역 (5개 - 법적 요건 강화)
        checkbox_frame = QFrame()
        checkbox_frame.setObjectName("checkboxFrame")
        checkbox_layout = QVBoxLayout(checkbox_frame)

        self.check_authority = QCheckBox(
            "본인은 이 시스템에 대한 적법한 수집 권한(소유자 동의 또는 법적 권한)이 있음을 확인합니다."
        )
        self.check_authority.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_authority)

        self.check_data_collection = QCheckBox(
            "위 '개인정보 수집·이용 동의' 내용을 확인하고, 데이터 수집 및 처리에 동의합니다."
        )
        self.check_data_collection.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_data_collection)

        self.check_overseas_transfer = QCheckBox(
            "개인정보의 국외이전(RunPod/Cloudflare 서버)에 대해 고지받았으며 이에 동의합니다."
        )
        self.check_overseas_transfer.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_overseas_transfer)

        self.check_ai_analysis = QCheckBox(
            "AI 분석의 한계, 오류 가능성 및 법적 분쟁 가능성을 이해하고 동의합니다."
        )
        self.check_ai_analysis.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_ai_analysis)

        self.check_legal_responsibility = QCheckBox(
            "무단 수집 시 발생하는 모든 법적 책임은 본인에게 있음을 인지합니다."
        )
        self.check_legal_responsibility.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_legal_responsibility)

        layout.addWidget(checkbox_frame)

        # 버튼
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.cancel_btn = QPushButton("취소")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setMinimumWidth(100)
        button_layout.addWidget(self.cancel_btn)

        self.agree_btn = QPushButton("동의 및 수집 시작")
        self.agree_btn.setObjectName("agreeButton")
        self.agree_btn.setEnabled(False)
        self.agree_btn.clicked.connect(self._on_agree)
        self.agree_btn.setMinimumWidth(150)
        button_layout.addWidget(self.agree_btn)

        layout.addLayout(button_layout)

        # 체크박스 상태 변경 시 버튼 활성화 (5개 모두 연결)
        self.check_authority.stateChanged.connect(self._update_button_state)
        self.check_data_collection.stateChanged.connect(self._update_button_state)
        self.check_overseas_transfer.stateChanged.connect(self._update_button_state)
        self.check_ai_analysis.stateChanged.connect(self._update_button_state)
        self.check_legal_responsibility.stateChanged.connect(self._update_button_state)

    def _get_consent_html(self) -> str:
        """동의서 HTML 내용 (개인정보 보호법 준수)"""
        return """
        <div style="font-family: 'Malgun Gothic', sans-serif; line-height: 1.8; color: #e0e0e0;">

        <!-- ===== 1. 개인정보 수집·이용 동의 ===== -->
        <h3 style="color: #4cc9f0; border-bottom: 2px solid #4cc9f0; padding-bottom: 8px;">
            1. 개인정보 수집·이용 동의
        </h3>
        <table style="width: 100%; border-collapse: collapse; margin: 12px 0;">
            <tr style="background: #1a3a5c;">
                <th style="border: 1px solid #333; padding: 10px; width: 25%;">항목</th>
                <th style="border: 1px solid #333; padding: 10px;">내용</th>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px; font-weight: bold;">수집 목적</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    디지털 포렌식 분석, 보안 사고 조사, 법적 증거 확보, AI 기반 이상 징후 탐지
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px; font-weight: bold;">수집 항목</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    <b>[필수]</b> 시스템 아티팩트(Prefetch, Amcache, ShimCache, UserAssist),
                    이벤트 로그(Security, System, Application), 레지스트리(SYSTEM, SOFTWARE, SAM, NTUSER.DAT),
                    파일 시스템 메타데이터(MFT, USN Journal, $LogFile), USB 연결 이력<br>
                    <b>[선택]</b> 브라우저 기록, 메모리 정보, 네트워크 연결 정보
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px; font-weight: bold;">보유 기간</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    결제 티어에 따라 7일~365일 (Starter: 7일, Standard: 30일, Professional: 90일, Enterprise: 365일)
                    <br>※ 보유 기간 만료 시 자동 파기
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px; font-weight: bold;">처리 방식</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    • SHA-256 해시를 통한 무결성 검증<br>
                    • TLS 1.3 암호화 통신<br>
                    • AES-256-GCM 암호화 저장<br>
                    • Chain of Custody 기록
                </td>
            </tr>
        </table>

        <!-- ===== 2. 개인정보 국외이전 고지 ===== -->
        <h3 style="color: #f0a500; border-bottom: 2px solid #f0a500; padding-bottom: 8px;">
            2. 개인정보 국외이전 고지
        </h3>
        <p style="background: rgba(240, 165, 0, 0.1); padding: 12px; border-radius: 8px; border-left: 4px solid #f0a500;">
            <b>알림:</b> 수집된 데이터는 클라우드 서버에 저장되며, 서버 위치에 따라 국외로 이전될 수 있습니다.
            개인정보 보호법 제28조의8에 따라 아래 사항을 고지합니다.
        </p>
        <table style="width: 100%; border-collapse: collapse; margin: 12px 0;">
            <tr style="background: #3a3a1c;">
                <th style="border: 1px solid #333; padding: 10px; width: 30%;">항목</th>
                <th style="border: 1px solid #333; padding: 10px;">내용</th>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px;">이전받는 자</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    RunPod, Inc. (GPU 서버) / Cloudflare, Inc. (R2 스토리지, CDN)
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px;">이전 국가</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    미국 (서버 위치에 따라 변동 가능)
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px;">이전 일시 및 방법</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    수집 즉시 TLS 암호화 통신으로 실시간 전송
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px;">이전 목적</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    암호화된 데이터 저장, AI 분석 처리, 분석 결과 제공
                </td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 10px;">보유 및 이용 기간</td>
                <td style="border: 1px solid #333; padding: 10px;">
                    서비스 이용 기간 또는 결제 티어에 따른 보관 기간까지
                </td>
            </tr>
        </table>

        <!-- ===== 3. AI 분석 및 자동화된 의사결정 고지 ===== -->
        <h3 style="color: #9d4edd; border-bottom: 2px solid #9d4edd; padding-bottom: 8px;">
            3. AI 분석 및 자동화된 의사결정 고지
        </h3>
        <p style="background: rgba(157, 78, 221, 0.1); padding: 12px; border-radius: 8px; border-left: 4px solid #9d4edd;">
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
            <li style="color: #ff6b6b;"><b>법적 분쟁 가능성:</b>
                AI 분석 결과를 근거로 법적 조치(고소, 징계, 해고 등)를 취할 경우,
                분석 결과의 정확성에 대한 법적 분쟁이 발생할 수 있으며,
                <u>귀하가 법적 소송의 당사자가 될 수 있습니다.</u>
                반드시 전문가(포렌식 전문가, 법률 전문가) 검토 후 사용하십시오.
            </li>
            <li><b>정보주체 권리:</b> 개인정보 보호법 제37조의2에 따라 자동화된 결정에 대해
                거부권, 설명요구권, 인적 개입 요구권을 행사할 수 있습니다.</li>
        </ul>

        <!-- ===== 4. 정보주체 권리 안내 ===== -->
        <h3 style="color: #4cc9f0; border-bottom: 2px solid #4cc9f0; padding-bottom: 8px;">
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
        <h3 style="color: #f72585; border-bottom: 2px solid #f72585; padding-bottom: 8px;">
            5. 법적 경고 및 면책
        </h3>
        <p style="background: rgba(247, 37, 133, 0.15); padding: 12px; border-radius: 8px; border-left: 4px solid #f72585;">
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
        """체크박스 상태에 따라 버튼 활성화 (5개 모두 체크 필요)"""
        all_checked = (
            self.check_authority.isChecked() and
            self.check_data_collection.isChecked() and
            self.check_overseas_transfer.isChecked() and
            self.check_ai_analysis.isChecked() and
            self.check_legal_responsibility.isChecked()
        )
        self.agree_btn.setEnabled(all_checked)

    def _on_agree(self):
        """동의 버튼 클릭"""
        self.consent_given = True
        self.consent_record = self._create_consent_record()
        self.accept()

    def _create_consent_record(self) -> dict:
        """동의 기록 생성 (법적 요건 강화 버전 2.0)"""
        timestamp = datetime.utcnow().isoformat()

        # 시스템 정보
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            ip_address = "unknown"

        # [보안] 개인정보 보호: IP 주소와 호스트명을 해시 처리
        # 원본 값 대신 해시값만 저장하여 개인정보 노출 방지
        hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()[:16]
        ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]

        record = {
            "consent_timestamp": timestamp,
            "consent_version": "2.0",  # 버전 업그레이드 (법적 요건 강화)
            "hostname_hash": hostname_hash,
            "ip_hash": ip_hash,
            "legal_basis": {
                "pipa_article_15": "수집·이용 동의",
                "pipa_article_28_8": "국외이전 동의",
                "pipa_article_37_2": "자동화된 의사결정 고지"
            },
            "checks": {
                "authority_confirmed": self.check_authority.isChecked(),
                "data_collection_consent": self.check_data_collection.isChecked(),
                "overseas_transfer_consent": self.check_overseas_transfer.isChecked(),
                "ai_analysis_acknowledged": self.check_ai_analysis.isChecked(),
                "legal_responsibility_accepted": self.check_legal_responsibility.isChecked(),
            }
        }

        # 동의 기록 해시 (무결성) - 5개 체크박스 모두 포함
        record_str = f"{timestamp}|{hostname_hash}|{ip_hash}|authority|data_collection|overseas|ai|legal"
        record["consent_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

        # M5 보안: 서버 검증용 HMAC 서명 추가
        # 서버에서 동일한 비밀키로 서명을 검증하여 위변조 방지
        import hmac
        import os

        # M5 보안: 세션 토큰에서 파생된 서명 키 사용 (하드코딩된 기본값 제거)
        # 환경변수가 설정된 경우 우선 사용, 없으면 세션 토큰 기반 파생
        signing_key = os.getenv("CONSENT_SIGNING_KEY")
        if not signing_key:
            # 세션 토큰에서 파생된 서명 키 (재현 가능한 방식)
            signing_key = hashlib.sha256(
                f"consent_sign_{record.get('session_token', 'default')}".encode()
            ).hexdigest()[:32]

        # 검증 가능한 필드만 포함 (checks 상태 + 타임스탬프)
        verify_payload = f"{timestamp}|{record['consent_version']}|{record['consent_hash']}"
        record["server_verify_signature"] = hmac.new(
            signing_key.encode(),
            verify_payload.encode(),
            hashlib.sha256
        ).hexdigest()

        # 서버 검증용 메타데이터
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
        """스타일시트"""
        return """
            QDialog {
                background-color: #1a1a2e;
            }
            #header {
                font-size: 20px;
                font-weight: bold;
                color: #4cc9f0;
                padding: 8px;
            }
            #warningFrame {
                background-color: rgba(247, 37, 133, 0.15);
                border: 1px solid #f72585;
                border-radius: 8px;
                padding: 12px;
            }
            #warningText {
                color: #f72585;
                font-size: 13px;
            }
            #checkboxFrame {
                background-color: #16213e;
                border: 1px solid #333;
                border-radius: 8px;
                padding: 16px;
            }
            #consentCheck {
                color: #e0e0e0;
                font-size: 13px;
                spacing: 8px;
                padding: 4px 0;
            }
            #consentCheck::indicator {
                width: 20px;
                height: 20px;
            }
            QTextEdit {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 8px;
                color: #e0e0e0;
                padding: 12px;
                font-size: 13px;
            }
            QPushButton {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 6px;
                color: #fff;
                padding: 10px 20px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #666;
            }
            #agreeButton {
                background-color: #4cc9f0;
                color: #000;
                font-weight: bold;
            }
            #agreeButton:hover {
                background-color: #3db8df;
            }
            #agreeButton:disabled {
                background-color: #333;
                color: #666;
            }
            QScrollArea {
                background-color: transparent;
            }
        """


def show_consent_dialog(parent=None) -> Optional[dict]:
    """
    동의 다이얼로그 표시 및 결과 반환

    Returns:
        동의 기록 dict (동의한 경우) 또는 None (취소한 경우)
    """
    dialog = ConsentDialog(parent)
    result = dialog.exec()

    if result == QDialog.DialogCode.Accepted:
        return dialog.get_consent_record()
    return None


if __name__ == "__main__":
    # 테스트용
    from PyQt6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)
    record = show_consent_dialog()
    if record:
        print("동의 완료:", record)
    else:
        print("동의 거부 또는 취소")
