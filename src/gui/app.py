"""
Main GUI Application

PyQt6-based graphical interface for the forensic collector.
"""
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QProgressBar, QListWidget, QListWidgetItem,
    QLineEdit, QCheckBox, QGroupBox, QMessageBox, QFrame, QTextEdit,
    QStatusBar, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon

from core.token_validator import TokenValidator, ValidationResult
from core.encryptor import FileEncryptor
from core.uploader import SyncUploader
from collectors.artifact_collector import ArtifactCollector, ARTIFACT_TYPES


class CollectorWindow(QMainWindow):
    """Main application window"""

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self.session_token = None
        self.session_id = None
        self.case_id = None
        self.collection_token = None
        self.server_url = None
        self.ws_url = None
        self.allowed_artifacts = []

        self.setup_ui()
        self.check_server_connection()

    def setup_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"{self.config['app_name']} v{self.config['version']}")
        self.setMinimumSize(800, 600)
        self.setStyleSheet(self._get_stylesheet())

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Header
        header = self._create_header()
        main_layout.addWidget(header)

        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Controls
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # Right panel - Log
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)

        splitter.setSizes([500, 300])
        main_layout.addWidget(splitter)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _create_header(self) -> QWidget:
        """Create header section"""
        frame = QFrame()
        frame.setObjectName("header")
        layout = QHBoxLayout(frame)

        title = QLabel(self.config['app_name'])
        title.setObjectName("title")
        layout.addWidget(title)

        layout.addStretch()

        # Server status indicator
        self.server_status = QLabel("Server: Checking...")
        self.server_status.setObjectName("serverStatus")
        layout.addWidget(self.server_status)

        return frame

    def _create_left_panel(self) -> QWidget:
        """Create left panel with controls"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Step 1: Token
        token_group = QGroupBox("1. Session Token")
        token_layout = QVBoxLayout(token_group)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Paste your session token here")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        token_layout.addWidget(self.token_input)

        token_btn_layout = QHBoxLayout()
        self.show_token_btn = QPushButton("Show")
        self.show_token_btn.setCheckable(True)
        self.show_token_btn.clicked.connect(self._toggle_token_visibility)
        self.validate_btn = QPushButton("Validate Token")
        self.validate_btn.clicked.connect(self._validate_token)
        token_btn_layout.addWidget(self.show_token_btn)
        token_btn_layout.addWidget(self.validate_btn)
        token_layout.addLayout(token_btn_layout)

        self.token_status = QLabel("")
        token_layout.addWidget(self.token_status)

        layout.addWidget(token_group)

        # Step 2: Artifacts
        artifacts_group = QGroupBox("2. Select Artifacts")
        artifacts_layout = QVBoxLayout(artifacts_group)

        self.select_all_cb = QCheckBox("Select All")
        self.select_all_cb.stateChanged.connect(self._toggle_select_all)
        artifacts_layout.addWidget(self.select_all_cb)

        self.artifact_checks: Dict[str, QCheckBox] = {}
        for artifact_type, info in ARTIFACT_TYPES.items():
            cb = QCheckBox(f"{info['name']} ({artifact_type})")
            cb.setEnabled(False)  # Enable after token validation
            if info.get('requires_admin'):
                cb.setToolTip("Requires administrator privileges")
            self.artifact_checks[artifact_type] = cb
            artifacts_layout.addWidget(cb)

        layout.addWidget(artifacts_group)

        # Step 3: Progress
        progress_group = QGroupBox("3. Collection Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        self.current_file_label = QLabel("Ready to collect")
        progress_layout.addWidget(self.current_file_label)

        self.collected_list = QListWidget()
        self.collected_list.setMaximumHeight(150)
        progress_layout.addWidget(self.collected_list)

        layout.addWidget(progress_group)

        # Buttons
        btn_layout = QHBoxLayout()
        self.collect_btn = QPushButton("Start Collection")
        self.collect_btn.setEnabled(False)
        self.collect_btn.clicked.connect(self._start_collection)
        self.collect_btn.setObjectName("primaryButton")

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_collection)

        btn_layout.addWidget(self.collect_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        layout.addStretch()

        return panel

    def _create_right_panel(self) -> QWidget:
        """Create right panel with log"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_group)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_text)

        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self.log_text.clear)
        log_layout.addWidget(clear_btn)

        layout.addWidget(log_group)

        return panel

    def _get_stylesheet(self) -> str:
        """Get application stylesheet"""
        return """
            QMainWindow {
                background-color: #1a1a2e;
            }
            QWidget {
                color: #eee;
                font-size: 12px;
            }
            #header {
                background-color: #16213e;
                border-radius: 8px;
                padding: 10px;
            }
            #title {
                font-size: 18px;
                font-weight: bold;
                color: #4cc9f0;
            }
            #serverStatus {
                color: #888;
            }
            QGroupBox {
                border: 1px solid #333;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background-color: #16213e;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #4cc9f0;
            }
            QLineEdit {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px;
                color: #fff;
            }
            QLineEdit:focus {
                border-color: #4cc9f0;
            }
            QPushButton {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px 16px;
                color: #fff;
            }
            QPushButton:hover {
                background-color: #1a4a7a;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #666;
            }
            #primaryButton {
                background-color: #4cc9f0;
                color: #000;
                font-weight: bold;
            }
            #primaryButton:hover {
                background-color: #3db8df;
            }
            QProgressBar {
                border: 1px solid #333;
                border-radius: 4px;
                background-color: #0f3460;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4cc9f0;
                border-radius: 3px;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QListWidget, QTextEdit {
                background-color: #0f3460;
                border: 1px solid #333;
                border-radius: 4px;
            }
            QStatusBar {
                background-color: #16213e;
                color: #888;
            }
        """

    def check_server_connection(self):
        """Check if server is reachable"""
        validator = TokenValidator(self.config['server_url'])
        if validator.check_server_health():
            self.server_status.setText("Server: Connected")
            self.server_status.setStyleSheet("color: #4cc9f0;")
            self._log("Server connection established")
        else:
            self.server_status.setText("Server: Disconnected")
            self.server_status.setStyleSheet("color: #f72585;")
            self._log("Warning: Cannot connect to server", error=True)

    def _toggle_token_visibility(self):
        """Toggle token visibility"""
        if self.show_token_btn.isChecked():
            self.token_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_token_btn.setText("Hide")
        else:
            self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_token_btn.setText("Show")

    def _toggle_select_all(self, state):
        """Toggle all artifact checkboxes"""
        checked = state == Qt.CheckState.Checked.value
        for cb in self.artifact_checks.values():
            if cb.isEnabled():
                cb.setChecked(checked)

    def _validate_token(self):
        """Validate the session token"""
        token = self.token_input.text().strip()
        if not token:
            QMessageBox.warning(self, "Error", "Please enter a session token")
            return

        self._log("Validating token...")
        self.validate_btn.setEnabled(False)

        validator = TokenValidator(self.config['server_url'])
        result = validator.validate(token)

        if result.valid:
            self.session_token = token
            self.session_id = result.session_id
            self.case_id = result.case_id
            self.collection_token = result.collection_token
            self.server_url = result.server_url or self.config['server_url']
            self.ws_url = result.ws_url or self.config['ws_url']
            self.allowed_artifacts = result.allowed_artifacts or list(ARTIFACT_TYPES.keys())

            self.token_status.setText(f"Valid - Case: {self.case_id[:8]}...")
            self.token_status.setStyleSheet("color: #4cc9f0;")
            self._log(f"Token validated. Case ID: {self.case_id}")
            self._log(f"Session ID: {self.session_id}")
            self._log(f"Allowed artifacts: {', '.join(self.allowed_artifacts)}")

            # Enable artifact selection
            for artifact_type, cb in self.artifact_checks.items():
                if artifact_type in self.allowed_artifacts or 'all' in self.allowed_artifacts:
                    cb.setEnabled(True)
                    cb.setChecked(True)

            self.collect_btn.setEnabled(True)
        else:
            self.token_status.setText(f"Invalid: {result.error}")
            self.token_status.setStyleSheet("color: #f72585;")
            self._log(f"Token validation failed: {result.error}", error=True)

        self.validate_btn.setEnabled(True)

    def _start_collection(self):
        """Start the collection process"""
        selected = [k for k, cb in self.artifact_checks.items() if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self, "Error", "Please select at least one artifact type")
            return

        self._log(f"Starting collection for: {', '.join(selected)}")

        # Disable controls
        self.collect_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.validate_btn.setEnabled(False)
        for cb in self.artifact_checks.values():
            cb.setEnabled(False)

        # Start worker thread
        self.worker = CollectionWorker(
            server_url=self.server_url,
            ws_url=self.ws_url,
            session_id=self.session_id,
            collection_token=self.collection_token,
            case_id=self.case_id,
            artifacts=selected,
        )
        self.worker.progress_updated.connect(self._update_progress)
        self.worker.file_collected.connect(self._add_collected_file)
        self.worker.log_message.connect(self._log)
        self.worker.finished.connect(self._collection_finished)
        self.worker.start()

    def _cancel_collection(self):
        """Cancel ongoing collection"""
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.cancel()
            self._log("Collection cancelled by user")

    def _update_progress(self, value: int, message: str):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        self.current_file_label.setText(message)

    def _add_collected_file(self, filename: str, success: bool):
        """Add file to collected list"""
        item = QListWidgetItem(filename)
        if success:
            item.setForeground(QColor("#4cc9f0"))
        else:
            item.setForeground(QColor("#f72585"))
        self.collected_list.addItem(item)
        self.collected_list.scrollToBottom()

    def _collection_finished(self, success: bool, message: str):
        """Handle collection completion"""
        # Re-enable controls
        self.collect_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.validate_btn.setEnabled(True)

        if success:
            self._log(f"Collection completed: {message}")
            QMessageBox.information(self, "Success", message)
        else:
            self._log(f"Collection failed: {message}", error=True)
            QMessageBox.critical(self, "Error", message)

        self.status_bar.showMessage("Ready")

    def _log(self, message: str, error: bool = False):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = "ERROR" if error else "INFO"
        color = "#f72585" if error else "#4cc9f0"

        html = f'<span style="color: #888;">[{timestamp}]</span> '
        html += f'<span style="color: {color};">[{prefix}]</span> '
        html += f'<span style="color: #eee;">{message}</span>'

        self.log_text.append(html)


class CollectionWorker(QThread):
    """Background worker for collection"""

    progress_updated = pyqtSignal(int, str)
    file_collected = pyqtSignal(str, bool)
    log_message = pyqtSignal(str, bool)
    finished = pyqtSignal(bool, str)

    def __init__(
        self,
        server_url: str,
        ws_url: str,
        session_id: str,
        collection_token: str,
        case_id: str,
        artifacts: List[str],
    ):
        super().__init__()
        self.server_url = server_url
        self.ws_url = ws_url
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.artifacts = artifacts
        self._cancelled = False

    def cancel(self):
        """Cancel the collection"""
        self._cancelled = True

    def run(self):
        """Run collection in background"""
        try:
            import tempfile
            output_dir = tempfile.mkdtemp(prefix="forensic_")

            collector = ArtifactCollector(output_dir)
            encryptor = FileEncryptor()

            collected_files = []
            total_artifacts = len(self.artifacts)

            for i, artifact_type in enumerate(self.artifacts):
                if self._cancelled:
                    self.finished.emit(False, "Collection cancelled")
                    return

                self.log_message.emit(f"Collecting {artifact_type}...", False)

                try:
                    files = list(collector.collect(artifact_type))

                    for file_path, metadata in files:
                        if self._cancelled:
                            break

                        # Encrypt file
                        filename = Path(file_path).name
                        self.progress_updated.emit(
                            int((i / total_artifacts) * 100),
                            f"Encrypting {filename}..."
                        )

                        enc_result = encryptor.encrypt_file(file_path)
                        metadata['encryption'] = {
                            'nonce': enc_result.nonce,
                            'original_hash': enc_result.original_hash,
                        }

                        collected_files.append((
                            enc_result.encrypted_path,
                            artifact_type,
                            metadata
                        ))

                        self.file_collected.emit(filename, True)

                except Exception as e:
                    self.log_message.emit(f"Error collecting {artifact_type}: {e}", True)

            if self._cancelled:
                self.finished.emit(False, "Collection cancelled")
                return

            # Upload files
            self.log_message.emit(f"Uploading {len(collected_files)} files...", False)

            uploader = SyncUploader(
                server_url=self.server_url,
                ws_url=self.ws_url,
                session_id=self.session_id,
                collection_token=self.collection_token,
                case_id=self.case_id,
            )

            success_count = 0
            for j, (file_path, artifact_type, metadata) in enumerate(collected_files):
                if self._cancelled:
                    break

                self.progress_updated.emit(
                    int(((j + 1) / len(collected_files)) * 100),
                    f"Uploading {Path(file_path).name}..."
                )

                result = uploader.upload_file(file_path, artifact_type, metadata)
                if result.success:
                    success_count += 1
                else:
                    self.log_message.emit(f"Upload failed: {result.error}", True)

            self.finished.emit(
                True,
                f"Collected and uploaded {success_count}/{len(collected_files)} files"
            )

        except Exception as e:
            self.finished.emit(False, str(e))
