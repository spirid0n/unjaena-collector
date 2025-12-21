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
        self.setMinimumSize(600, 700)
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

        # 체크박스 영역
        checkbox_frame = QFrame()
        checkbox_frame.setObjectName("checkboxFrame")
        checkbox_layout = QVBoxLayout(checkbox_frame)

        self.check_authority = QCheckBox(
            "본인은 이 시스템에 대한 적법한 수집 권한이 있음을 확인합니다."
        )
        self.check_authority.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_authority)

        self.check_data_consent = QCheckBox(
            "수집된 데이터의 서버 전송 및 분석에 동의합니다."
        )
        self.check_data_consent.setObjectName("consentCheck")
        checkbox_layout.addWidget(self.check_data_consent)

        self.check_legal_responsibility = QCheckBox(
            "무단 수집 시 발생하는 법적 책임은 본인에게 있음을 인지합니다."
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

        # 체크박스 상태 변경 시 버튼 활성화
        self.check_authority.stateChanged.connect(self._update_button_state)
        self.check_data_consent.stateChanged.connect(self._update_button_state)
        self.check_legal_responsibility.stateChanged.connect(self._update_button_state)

    def _get_consent_html(self) -> str:
        """동의서 HTML 내용"""
        return """
        <div style="font-family: 'Malgun Gothic', sans-serif; line-height: 1.6; color: #e0e0e0;">

        <h3 style="color: #4cc9f0; border-bottom: 1px solid #333; padding-bottom: 8px;">
            1. 수집 목적
        </h3>
        <p>
            본 수집 도구는 디지털 포렌식 분석을 위해 시스템 아티팩트를 수집합니다.
            수집된 데이터는 보안 사고 조사, 내부 감사, 법적 증거 확보 등의 목적으로 사용됩니다.
        </p>

        <h3 style="color: #4cc9f0; border-bottom: 1px solid #333; padding-bottom: 8px;">
            2. 수집 대상 데이터
        </h3>
        <ul>
            <li><b>프로그램 실행 기록</b>: Prefetch, Amcache, ShimCache, UserAssist</li>
            <li><b>시스템 이벤트 로그</b>: Security, System, Application 등</li>
            <li><b>레지스트리 정보</b>: SYSTEM, SOFTWARE, SAM, NTUSER.DAT</li>
            <li><b>브라우저 기록</b>: 방문 기록, 다운로드 기록, 쿠키</li>
            <li><b>USB 연결 이력</b>: 외부 장치 연결 기록</li>
            <li><b>파일 시스템 메타데이터</b>: MFT, USN Journal, $LogFile</li>
            <li><b>메모리 정보</b>: 프로세스, 네트워크 연결, 모듈 (선택적)</li>
        </ul>

        <h3 style="color: #4cc9f0; border-bottom: 1px solid #333; padding-bottom: 8px;">
            3. 데이터 처리 방식
        </h3>
        <ul>
            <li>수집된 데이터는 <b>무결성 보장</b>을 위해 SHA-256 해시가 생성됩니다.</li>
            <li>모든 데이터는 <b>TLS 암호화 통신</b>으로 서버에 전송됩니다.</li>
            <li>서버에서 <b>AES-256-GCM</b>으로 암호화되어 안전하게 저장됩니다.</li>
            <li><b>연계보관성(Chain of Custody)</b>이 기록되어 법적 증거능력을 확보합니다.</li>
        </ul>

        <h3 style="color: #f72585; border-bottom: 1px solid #333; padding-bottom: 8px;">
            4. 법적 주의사항
        </h3>
        <p style="background: rgba(247, 37, 133, 0.1); padding: 12px; border-radius: 8px; border-left: 4px solid #f72585;">
            <b>⚠️ 경고:</b> 타인의 시스템에서 권한 없이 데이터를 수집하는 행위는
            「정보통신망 이용촉진 및 정보보호 등에 관한 법률」,
            「형법」(컴퓨터 등 사용 사기) 등 관련 법률에 의해 처벌받을 수 있습니다.
        </p>
        <ul>
            <li>반드시 <b>시스템 소유자의 동의</b> 또는 <b>법적 권한</b>이 있는 경우에만 사용하십시오.</li>
            <li>기업 내부 조사 시 <b>회사 정책 및 법무팀 검토</b>를 받으시기 바랍니다.</li>
            <li>무단 수집으로 인한 <b>모든 법적 책임은 사용자</b>에게 있습니다.</li>
        </ul>

        <h3 style="color: #4cc9f0; border-bottom: 1px solid #333; padding-bottom: 8px;">
            5. 동의 철회
        </h3>
        <p>
            수집이 시작된 이후에는 이미 전송된 데이터에 대한 동의 철회가 제한될 수 있습니다.
            동의 철회 요청은 서비스 관리자에게 문의하시기 바랍니다.
        </p>

        </div>
        """

    def _update_button_state(self):
        """체크박스 상태에 따라 버튼 활성화"""
        all_checked = (
            self.check_authority.isChecked() and
            self.check_data_consent.isChecked() and
            self.check_legal_responsibility.isChecked()
        )
        self.agree_btn.setEnabled(all_checked)

    def _on_agree(self):
        """동의 버튼 클릭"""
        self.consent_given = True
        self.consent_record = self._create_consent_record()
        self.accept()

    def _create_consent_record(self) -> dict:
        """동의 기록 생성"""
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
            "consent_version": "1.1",  # 버전 업데이트 (해시 처리 적용)
            "hostname_hash": hostname_hash,  # 원본 대신 해시
            "ip_hash": ip_hash,  # 원본 대신 해시
            "checks": {
                "authority_confirmed": self.check_authority.isChecked(),
                "data_consent": self.check_data_consent.isChecked(),
                "legal_responsibility": self.check_legal_responsibility.isChecked(),
            }
        }

        # 동의 기록 해시 (무결성) - 해시값 사용
        record_str = f"{timestamp}|{hostname_hash}|{ip_hash}|authority|data|legal"
        record["consent_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

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
