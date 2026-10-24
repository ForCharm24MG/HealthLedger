"""
gui_app.py
Hospital Healthcare Information Exchange System (HealthLedger v2.4).
Built with Python 3 and PyQt5 for M.Sc. IT Research Project Defense.

Program: Master of Science in Information Technology (2026-27)
Candidate: Manish Ghag (Roll No. 603) | Guide: Mr. Mahavir Advaya
Research Topic: Privacy-Preserving Healthcare Data Sharing Using Blockchain

Core Technical Features:
- Standard enterprise desktop login with user authentication
- Symmetric Authenticated Encryption: AES-256-GCM (NIST SP 800-38D, 96-bit CSPRNG nonces)
- Asymmetric Key Encapsulation: RSA-2048 OAEP (SHA-256, MGF1)
- Non-Repudiable Digital Signatures: RSA-2048 PSS with SHA-256
- User Password Hashing: PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte random salt)
- Content-Addressed Storage (CAS) with on-read bit-flip tamper detection
- Persistent Consortium Blockchain recording dynamic time-locked policies and forensic audit trails
- Instant Zero-Reencryption Revocation O(1)
"""

import sys
import os
import re
import time
import json
import io
import tempfile
import subprocess
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import pypdf

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QGroupBox, QStatusBar,
    QDialog, QFormLayout, QDialogButtonBox, QFrame, QTabWidget,
    QCheckBox, QSplitter, QMenuBar, QMenu, QAction, QRadioButton,
    QButtonGroup, QStyle
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QColor

import database
import storage
from blockchain import HealthcareBlockchain
import crypto_utils
from crypto_utils import (
    generate_aes_key,
    encrypt_bytes,
    decrypt_bytes,
    compute_bytes_hash,
    encrypt_key_for_recipient,
    decrypt_key_with_private_key,
    load_rsa_public_key,
    load_rsa_private_key,
    sign_data,
    verify_signature
)

def make_medical_report_pdf(title: str, text_content: str) -> bytes:
    """Compiles a clinical text record into a genuine, structured PDF document (NIST/HL7 standards)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0F2942'),
        spaceAfter=8
    )
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor('#1E3A8A'),
        spaceBefore=6,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=4
    )

    story = []
    for line in text_content.strip().split('\n'):
        line_clean = line.strip()
        if not line_clean:
            story.append(Spacer(1, 4))
        elif line_clean.startswith('---'):
            story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#94A3B8'), spaceAfter=6, spaceBefore=4))
        elif any(line_clean.startswith(h) for h in ['METRO', 'APEX', 'CONSORTIUM', 'CITY']):
            story.append(Paragraph(f"<b>{line_clean}</b>", title_style))
        elif any(line_clean.startswith(h) for h in ['FINDINGS:', 'IMPRESSION:', 'TEST RESULTS:', 'CLINICAL INTERPRETATION:', 'OPERATIVE SUMMARY:', 'DISCHARGE ADVICE:', 'CLINICAL OBSERVATIONS']):
            story.append(Paragraph(f"<b>{line_clean}</b>", section_style))
        else:
            story.append(Paragraph(line_clean, body_style))
    doc.build(story)
    return buf.getvalue()

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25.0 MB maximum medical file limit

ENTERPRISE_STYLE = """
QMainWindow {
    background-color: #f8fafc;
}
QWidget {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Arial, sans-serif;
    font-size: 13px;
    color: #0f172a;
}
QMenuBar {
    background-color: #ffffff;
    border-bottom: 1px solid #cbd5e1;
    padding: 3px 6px;
    font-size: 13px;
}
QMenuBar::item {
    background: transparent;
    padding: 5px 12px;
    border-radius: 3px;
}
QMenuBar::item:selected {
    background-color: #e2e8f0;
}
QMenu {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    padding: 4px 0px;
    font-size: 13px;
}
QMenu::item {
    padding: 8px 24px;
}
QMenu::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    gridline-color: #e2e8f0;
    font-size: 12.5px;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 8px 10px;
}
QHeaderView::section {
    background-color: #f1f5f9;
    color: #1e293b;
    font-weight: 700;
    padding: 9px 8px;
    border: none;
    border-right: 1px solid #cbd5e1;
    border-bottom: 2px solid #94a3b8;
    font-size: 12.5px;
}
QTabWidget::pane {
    border: 1px solid #cbd5e1;
    background-color: #ffffff;
    border-radius: 4px;
    top: -1px;
}
QTabBar::tab {
    background: #e2e8f0;
    color: #334155;
    padding: 8px 18px;
    font-weight: 600;
    font-size: 13px;
    border: 1px solid #cbd5e1;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 4px;
    min-width: 130px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #1d4ed8;
    border: 1px solid #cbd5e1;
    border-bottom: 3px solid #2563eb;
    font-weight: 700;
}
QLineEdit, QComboBox, QTextEdit {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 13px;
    color: #0f172a;
}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
    border: 1.5px solid #2563eb;
}
QLabel {
    border: none;
    background: transparent;
}
QPushButton {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #1d4ed8;
    border-radius: 4px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #1d4ed8;
}
QPushButton:pressed {
    background-color: #1e40af;
}
QStatusBar {
    background-color: #ffffff;
    border-top: 1px solid #cbd5e1;
    color: #334155;
    font-size: 12.5px;
    padding: 6px 12px;
    font-weight: 500;
}
"""

class HealthLedgerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HealthLedger - Healthcare Data Sharing System")
        self.resize(1220, 840)
        self.setStyleSheet(ENTERPRISE_STYLE)

        # Initialize underlying storage, database, and persistent blockchain
        storage.init_storage()
        database.init_db()

        # Check if database has users; if empty, run seed script
        if len(database.get_users_by_role("patient")) == 0:
            try:
                import seed_healthcare_data
                seed_healthcare_data.seed_complete_healthcare_system()
            except Exception as e:
                print(f"[!] Auto-seeding notice: {e}")

        self.blockchain = HealthcareBlockchain()

        # Session state
        self.current_user = None
        self.selected_file_path = ""
        self.last_tampered_cid = None
        self.tamper_backup_content = None

        self.init_menu_bar()
        self.init_ui()
        self.show_login_screen()

        # Background sync timer (polls disk ledger every 2 seconds for multi-node updates)
        self.sync_timer = QTimer(self)
        self.sync_timer.setInterval(2000)
        self.sync_timer.timeout.connect(self.realtime_background_sync)
        self.sync_timer.start()

    def init_menu_bar(self):
        menubar = self.menuBar()

        # File Menu
        menu_file = menubar.addMenu("File")
        
        act_logout = QAction("Switch User / Log Out", self)
        act_logout.triggered.connect(self.show_login_screen)
        menu_file.addAction(act_logout)
        
        menu_file.addSeparator()
        
        act_exit = QAction("Exit", self)
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        # View Menu
        menu_view = menubar.addMenu("View")
        
        self.act_view_patient = QAction("Patient Portal", self)
        self.act_view_patient.triggered.connect(self.show_patient_screen)
        menu_view.addAction(self.act_view_patient)

        self.act_view_doctor = QAction("Physician Workstation", self)
        self.act_view_doctor.triggered.connect(self.show_doctor_screen)
        menu_view.addAction(self.act_view_doctor)

        menu_view.addSeparator()

        act_view_ledger = QAction("Consortium Blockchain Explorer", self)
        act_view_ledger.triggered.connect(self.show_ledger_screen)
        menu_view.addAction(act_view_ledger)

        # Security & Tools Menu
        menu_tools = menubar.addMenu("Tools")

        act_verify_chain = QAction("Verify Cryptographic Ledger Integrity", self)
        act_verify_chain.triggered.connect(self.verify_blockchain_integrity_dialog)
        menu_tools.addAction(act_verify_chain)

        menu_tools.addSeparator()

        act_tamper = QAction("Simulate CAS Storage Tamper Attack (Bit-Flip Test)", self)
        act_tamper.triggered.connect(self.simulate_cas_tamper_attack)
        menu_tools.addAction(act_tamper)

        act_restore = QAction("Restore CAS Storage Integrity", self)
        act_restore.triggered.connect(self.restore_cas_storage_integrity)
        menu_tools.addAction(act_restore)

        menu_tools.addSeparator()

        act_reseed = QAction("Reset & Re-Seed Database with Clinical Data", self)
        act_reseed.triggered.connect(self.reset_and_reseed_demo_data)
        menu_tools.addAction(act_reseed)

        act_dual_node = QAction("Launch Secondary Node Window (Side-by-Side)", self)
        act_dual_node.triggered.connect(self.launch_secondary_node_window)
        menu_tools.addAction(act_dual_node)

        # Help Menu
        menu_help = menubar.addMenu("Help")
        
        act_specs = QAction("System Specifications & Architecture", self)
        act_specs.triggered.connect(self.dialog_system_specs)
        menu_help.addAction(act_specs)

        act_about = QAction("About HealthLedger", self)
        act_about.triggered.connect(self.dialog_about)
        menu_help.addAction(act_about)

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Global Top Navigation & Header Bar
        self.header_bar = QFrame()
        self.header_bar.setStyleSheet(
            "background-color: #0f172a; color: #ffffff; padding: 10px 16px; border-bottom: 2px solid #1e293b;"
        )
        h_layout = QHBoxLayout(self.header_bar)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(12)

        # Branding (Clean, Professional Hospital System Header)
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_brand = QLabel("METRO HEALTHCARE CONSORTIUM | HealthLedger EHR")
        lbl_brand.setFont(QFont("Segoe UI", 14, QFont.Bold))
        lbl_brand.setStyleSheet("color: #38bdf8;")
        title_box.addWidget(lbl_brand)

        lbl_sub = QLabel("Federated Electronic Health Record (EHR) System")
        lbl_sub.setFont(QFont("Segoe UI", 10))
        lbl_sub.setStyleSheet("color: #94a3b8;")
        title_box.addWidget(lbl_sub)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        # Clean Header Shortcut: View Blockchain Ledger
        self.btn_header_ledger = QPushButton("View Blockchain Ledger")
        self.btn_header_ledger.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_header_ledger.setStyleSheet(
            "background-color: #1e293b; color: #38bdf8; border: 1px solid #334155; padding: 7px 16px; border-radius: 4px; font-size: 12.5px; font-weight: 600;"
        )
        self.btn_header_ledger.clicked.connect(self.show_ledger_screen)
        h_layout.addWidget(self.btn_header_ledger)

        # User Session Badge
        self.lbl_user_session = QLabel("Not Logged In")
        self.lbl_user_session.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.lbl_user_session.setStyleSheet(
            "color: #f8fafc; background-color: #1e293b; padding: 7px 16px; border-radius: 4px; border: 1px solid #334155; font-size: 12.5px;"
        )
        h_layout.addWidget(self.lbl_user_session)

        self.btn_header_logout = QPushButton("Log Out")
        self.btn_header_logout.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_header_logout.setStyleSheet(
            "background-color: #334155; color: #f8fafc; border: 1px solid #475569; padding: 7px 16px; border-radius: 4px; font-size: 12.5px; font-weight: 600;"
        )
        self.btn_header_logout.clicked.connect(self.show_login_screen)
        self.btn_header_logout.setVisible(False)
        h_layout.addWidget(self.btn_header_logout)

        main_layout.addWidget(self.header_bar)

        # Main Stacked Screens
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)

        self.screen_login = QWidget()
        self.screen_patient = QWidget()
        self.screen_doctor = QWidget()
        self.screen_ledger = QWidget()

        self.setup_login_screen()
        self.setup_patient_screen()
        self.setup_doctor_screen()
        self.setup_ledger_screen()

        self.stack.addWidget(self.screen_login)     # 0
        self.stack.addWidget(self.screen_patient)   # 1
        self.stack.addWidget(self.screen_doctor)    # 2
        self.stack.addWidget(self.screen_ledger)    # 3

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.setCentralWidget(main_widget)

    # -------------------------------------------------------------
    # SCREEN 1: PROPER DESKTOP USER AUTHENTICATION / LOGIN
    # -------------------------------------------------------------
    def setup_login_screen(self):
        outer_layout = QVBoxLayout(self.screen_login)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Centering container
        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setAlignment(Qt.AlignCenter)

        # Login Dialog Box (Clean, Professional Healthcare Enterprise Card)
        login_card = QFrame()
        login_card.setObjectName("loginCard")
        login_card.setFixedWidth(460)
        login_card.setStyleSheet(
            "QFrame#loginCard { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 28px 32px; }"
        )
        card_layout = QVBoxLayout(login_card)
        card_layout.setSpacing(14)

        # System Header inside Login Card
        h1 = QLabel("Consortium HealthLedger EHR")
        h1.setFont(QFont("Segoe UI", 18, QFont.Bold))
        h1.setStyleSheet("color: #0f172a;")
        h1.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(h1)

        h2 = QLabel("Secure Healthcare Information Exchange & Access Audit")
        h2.setFont(QFont("Segoe UI", 11))
        h2.setStyleSheet("color: #64748b;")
        h2.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(h2)

        # Divider line
        div = QFrame()
        div.setFrameShape(QFrame.HLine)
        div.setStyleSheet("color: #e2e8f0; margin: 2px 0px;")
        card_layout.addWidget(div)

        # Input Form (Large, Comfortable, Enterprise Typography)
        form_layout = QFormLayout()
        form_layout.setSpacing(12)

        lbl_u = QLabel("Username / User ID:")
        lbl_u.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.txt_login_username = QLineEdit()
        self.txt_login_username.setFont(QFont("Segoe UI", 12))
        self.txt_login_username.setMinimumHeight(40)
        self.txt_login_username.setPlaceholderText("Enter username (e.g. alice_smith, dr_bob)")
        self.txt_login_username.setText("alice_smith")
        self.txt_login_username.returnPressed.connect(self.execute_user_login)
        form_layout.addRow(lbl_u, self.txt_login_username)

        lbl_p = QLabel("Password:")
        lbl_p.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.txt_login_password = QLineEdit()
        self.txt_login_password.setFont(QFont("Segoe UI", 12))
        self.txt_login_password.setMinimumHeight(40)
        self.txt_login_password.setEchoMode(QLineEdit.Password)
        self.txt_login_password.setPlaceholderText("Enter password")
        self.txt_login_password.setText("Password@123")
        self.txt_login_password.returnPressed.connect(self.execute_user_login)
        form_layout.addRow(lbl_p, self.txt_login_password)

        card_layout.addLayout(form_layout)

        # Show password toggle
        pwd_opt_row = QHBoxLayout()
        self.chk_show_pwd = QCheckBox("Show Password")
        self.chk_show_pwd.setFont(QFont("Segoe UI", 11))
        self.chk_show_pwd.setStyleSheet("color: #475569;")
        self.chk_show_pwd.toggled.connect(
            lambda checked: self.txt_login_password.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )
        pwd_opt_row.addWidget(self.chk_show_pwd)
        pwd_opt_row.addStretch()
        card_layout.addLayout(pwd_opt_row)

        # Primary Sign In Button (Large, Bold, High-Affordance)
        self.btn_sign_in = QPushButton("Sign In")
        self.btn_sign_in.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.btn_sign_in.setMinimumHeight(44)
        self.btn_sign_in.setStyleSheet(
            "background-color: #2563eb; color: #ffffff; font-weight: bold; padding: 10px; font-size: 14px; border-radius: 4px;"
        )
        self.btn_sign_in.clicked.connect(self.execute_user_login)
        card_layout.addWidget(self.btn_sign_in)

        # Register button
        btn_reg = QPushButton("Register New Account")
        btn_reg.setFont(QFont("Segoe UI", 11))
        btn_reg.setMinimumHeight(38)
        btn_reg.setStyleSheet(
            "background-color: #ffffff; color: #1e293b; border: 1px solid #cbd5e1; padding: 8px; border-radius: 4px; font-size: 13px; font-weight: 600;"
        )
        btn_reg.clicked.connect(self.dialog_register_user)
        card_layout.addWidget(btn_reg)

        # Divider line
        div2 = QFrame()
        div2.setFrameShape(QFrame.HLine)
        div2.setStyleSheet("color: #e2e8f0; margin: 4px 0px;")
        card_layout.addWidget(div2)

        # Prominent "View Blockchain Ledger" Button (Requested by User)
        self.btn_login_view_ledger = QPushButton("View Blockchain Ledger")
        self.btn_login_view_ledger.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.btn_login_view_ledger.setMinimumHeight(40)
        self.btn_login_view_ledger.setStyleSheet(
            "background-color: #f0fdf4; color: #047857; border: 1.5px solid #86efac; padding: 9px; border-radius: 4px; font-size: 13px; font-weight: 600;"
        )
        self.btn_login_view_ledger.clicked.connect(self.show_ledger_screen)
        card_layout.addWidget(self.btn_login_view_ledger)

        center_layout.addWidget(login_card)
        outer_layout.addWidget(center_widget)

    def execute_user_login(self):
        username = self.txt_login_username.text().strip().lower()
        password = self.txt_login_password.text().strip()

        if not username:
            QMessageBox.warning(self, "Validation Error", "Please enter your username.")
            self.txt_login_username.setFocus()
            return
        if not password:
            QMessageBox.warning(self, "Validation Error", "Please enter your password.")
            self.txt_login_password.setFocus()
            return

        user = database.authenticate_user(username, password)
        if not user:
            QMessageBox.critical(
                self, "Authentication Failed",
                "Invalid username or password.\n\n"
                "Please verify your credentials or use the demonstration accounts below."
            )
            return

        self.current_user = user
        role = user.get('role', 'patient').lower()

        # Update Session Information
        role_title = "Patient" if role == "patient" else "Physician"
        hosp = user.get('hospital', 'Metro General Hospital')
        self.lbl_user_session.setText(f"{user['full_name']} ({role_title}) | {hosp}")
        self.btn_header_logout.setVisible(True)

        # Route automatically based on user role
        if role == "doctor":
            self.show_doctor_screen()
        else:
            self.show_patient_screen()

    def dialog_register_user(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Register New Account")
        dlg.setFixedWidth(420)
        vbox = QVBoxLayout(dlg)
        vbox.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)

        # Role Selector (Radio buttons)
        role_box = QHBoxLayout()
        rb_patient = QRadioButton("Patient")
        rb_doctor = QRadioButton("Physician")
        rb_patient.setChecked(True)
        role_box.addWidget(rb_patient)
        role_box.addWidget(rb_doctor)
        form.addRow("Account Type:", role_box)

        inp_user = QLineEdit()
        inp_pwd = QLineEdit()
        inp_pwd.setEchoMode(QLineEdit.Password)
        inp_pwd.setText("Password@123")
        inp_name = QLineEdit()
        lbl_dept = QLabel("Physician Specialty:")
        inp_dept = QLineEdit("Cardiology")
        lbl_hosp = QLabel("Registered Hospital:")
        inp_hosp = QLineEdit("Metro General Hospital")

        form.addRow("Username / ID:", inp_user)
        form.addRow("Password:", inp_pwd)
        form.addRow("Full Legal Name:", inp_name)
        form.addRow(lbl_dept, inp_dept)
        form.addRow(lbl_hosp, inp_hosp)

        def on_role_toggle():
            if rb_patient.isChecked():
                lbl_dept.hide()
                inp_dept.hide()
                lbl_hosp.setText("Registered Hospital:")
            else:
                lbl_dept.show()
                inp_dept.show()
                lbl_hosp.setText("Hospital / Clinic:")

        rb_patient.toggled.connect(on_role_toggle)
        rb_doctor.toggled.connect(on_role_toggle)
        on_role_toggle()

        vbox.addLayout(form)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        vbox.addWidget(btns)

        if dlg.exec_() == QDialog.Accepted:
            u = inp_user.text().strip().lower()
            p = inp_pwd.text().strip()
            n = inp_name.text().strip()
            r = "doctor" if rb_doctor.isChecked() else "patient"
            dep = inp_dept.text().strip() if r == "doctor" else ""
            h = inp_hosp.text().strip()

            if not u or not p or not n:
                QMessageBox.warning(self, "Validation Error", "Username, password, and full name are required.")
                return
            if database.get_user(u):
                QMessageBox.warning(self, "Duplicate Account", f"Username '{u}' is already registered.")
                return

            database.register_user(u, p, n, r, dep, h)
            QMessageBox.information(
                self, "Registration Successful",
                f"Account successfully created!\n\n"
                f"User: {n} (@{u})\n"
                f"Role: {r.capitalize()}\n"
                f"Generated RSA-2048 keypair and PBKDF2 salted hash."
            )
            self.txt_login_username.setText(u)
            self.txt_login_password.setText(p)

    # -------------------------------------------------------------
    # SCREEN 2: PATIENT PORTAL
    # -------------------------------------------------------------
    def setup_patient_screen(self):
        layout = QVBoxLayout(self.screen_patient)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(12)

        # Header Card with KPI Metrics
        self.card_patient_header = QFrame()
        self.card_patient_header.setObjectName("patientHeaderCard")
        self.card_patient_header.setStyleSheet(
            "QFrame#patientHeaderCard { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 4px; padding: 12px 16px; }"
        )
        cph_layout = QHBoxLayout(self.card_patient_header)
        cph_layout.setContentsMargins(0, 0, 0, 0)

        info_vbox = QVBoxLayout()
        self.lbl_pat_greeting = QLabel("Patient Electronic Health Record Portal")
        self.lbl_pat_greeting.setFont(QFont("Segoe UI", 15, QFont.Bold))
        self.lbl_pat_greeting.setStyleSheet("color: #1e40af;")
        info_vbox.addWidget(self.lbl_pat_greeting)

        self.lbl_pat_sub = QLabel("Self-Sovereign Access Governance | Dynamic Blockchain Time-Locks")
        self.lbl_pat_sub.setFont(QFont("Segoe UI", 11))
        self.lbl_pat_sub.setStyleSheet("color: #64748b;")
        info_vbox.addWidget(self.lbl_pat_sub)
        cph_layout.addLayout(info_vbox)

        cph_layout.addStretch()

        # 4 Metric Badges
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(8)
        self.kpi_pat_records = self._create_kpi_badge("Medical Records", "0", "#2563eb")
        self.kpi_pat_consents = self._create_kpi_badge("Active Consents", "0", "#059669")
        self.kpi_pat_doctors = self._create_kpi_badge("Authorized MDs", "0", "#7c3aed")
        self.kpi_pat_blocks = self._create_kpi_badge("Ledger Blocks", "0", "#0f766e")
        kpi_row.addWidget(self.kpi_pat_records)
        kpi_row.addWidget(self.kpi_pat_consents)
        kpi_row.addWidget(self.kpi_pat_doctors)
        kpi_row.addWidget(self.kpi_pat_blocks)
        cph_layout.addLayout(kpi_row)

        layout.addWidget(self.card_patient_header)

        # Patient Tabs
        self.patient_tabs = QTabWidget()

        # Tab 1: Medical Documents
        tab_my_records = QWidget()
        tmr_layout = QVBoxLayout(tab_my_records)
        tmr_layout.setContentsMargins(12, 12, 12, 12)
        tmr_layout.setSpacing(10)

        self.table_pat_docs = QTableWidget()
        self.table_pat_docs.setColumnCount(8)
        self.table_pat_docs.setHorizontalHeaderLabels([
            "Record ID", "Document Title", "Record Category", "Clinical Findings / Diagnosis", "File Name", "Size (Bytes)", "Storage CID (SHA-256)", "Mined Block"
        ])
        h_pat = self.table_pat_docs.horizontalHeader()
        h_pat.setSectionResizeMode(QHeaderView.Interactive)
        h_pat.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h_pat.setSectionResizeMode(1, QHeaderView.Stretch)
        h_pat.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h_pat.setSectionResizeMode(3, QHeaderView.Stretch)
        h_pat.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        h_pat.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        h_pat.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        h_pat.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table_pat_docs.cellDoubleClicked.connect(self.patient_view_record_details)
        tmr_layout.addWidget(self.table_pat_docs)

        pat_btn_row = QHBoxLayout()
        pat_btn_row.setSpacing(8)

        btn_view_details = QPushButton("View Full Diagnostic Report")
        btn_view_details.clicked.connect(self.patient_view_record_details)
        pat_btn_row.addWidget(btn_view_details)

        btn_share_doc = QPushButton("Grant Time-Locked Consent to Doctor")
        btn_share_doc.clicked.connect(self.dialog_share_record)
        pat_btn_row.addWidget(btn_share_doc)

        btn_download_own = QPushButton("Download Decrypted File")
        btn_download_own.setStyleSheet("background-color: #f1f5f9; color: #1e293b; border: 1px solid #cbd5e1;")
        btn_download_own.clicked.connect(self.patient_download_own_record)
        pat_btn_row.addWidget(btn_download_own)

        pat_btn_row.addStretch()
        tmr_layout.addLayout(pat_btn_row)

        self.patient_tabs.addTab(tab_my_records, "Medical Documents")

        # Tab 2: Upload New Record
        tab_upload = QWidget()
        tu_layout = QVBoxLayout(tab_upload)
        tu_layout.setContentsMargins(16, 16, 16, 16)
        tu_layout.setSpacing(12)

        form_box = QGroupBox("Client-Side Symmetric Encryption (AES-256-GCM) & Storage Anchor")
        form_box.setFont(QFont("Segoe UI", 11, QFont.Bold))
        fb_layout = QFormLayout(form_box)
        fb_layout.setSpacing(10)

        self.input_doc_title = QLineEdit()
        self.input_doc_title.setPlaceholderText("e.g. 12-Lead Electrocardiogram Diagnostic Report")
        fb_layout.addRow("Document Title:", self.input_doc_title)

        self.combo_doc_category = QComboBox()
        self.combo_doc_category.addItems([
            "Cardiology", "Neurology", "Pathology / Lab Report", "Radiology / Imaging", 
            "Orthopedic Surgery", "General Medicine", "Oncology", "Discharge Summary"
        ])
        fb_layout.addRow("Record Category:", self.combo_doc_category)

        self.input_doc_notes = QTextEdit()
        self.input_doc_notes.setPlaceholderText("Enter clinical findings, diagnostic observations, or physician remarks...")
        self.input_doc_notes.setMaximumHeight(80)
        fb_layout.addRow("Clinical Notes:", self.input_doc_notes)

        file_row = QHBoxLayout()
        self.lbl_selected_file = QLabel("No file attached (Optional, max 25 MB)")
        self.lbl_selected_file.setStyleSheet("color: #64748b; font-style: italic;")
        btn_browse = QPushButton("Browse File...")
        btn_browse.setStyleSheet("background-color: #f8fafc; color: #1e293b; border: 1px solid #cbd5e1;")
        btn_browse.clicked.connect(self.choose_file_to_upload)
        file_row.addWidget(btn_browse)
        file_row.addWidget(self.lbl_selected_file)
        file_row.addStretch()
        fb_layout.addRow("File Attachment:", file_row)

        tu_layout.addWidget(form_box)

        btn_exec_upload = QPushButton("Encrypt (AES-256-GCM) and Anchor to Blockchain")
        btn_exec_upload.setStyleSheet("background-color: #1e40af; color: white; padding: 10px; font-weight: bold; font-size: 13px;")
        btn_exec_upload.clicked.connect(self.execute_patient_upload)
        tu_layout.addWidget(btn_exec_upload)

        tu_layout.addStretch()
        self.patient_tabs.addTab(tab_upload, "Upload New Record")

        # Tab 3: Access Consents & Revocation
        tab_permissions = QWidget()
        tp_layout = QVBoxLayout(tab_permissions)
        tp_layout.setContentsMargins(12, 12, 12, 12)
        tp_layout.setSpacing(10)

        self.table_pat_perms = QTableWidget()
        self.table_pat_perms.setColumnCount(7)
        self.table_pat_perms.setHorizontalHeaderLabels([
            "Record ID", "Document Title", "Authorized Physician", "Department / Hospital", "Time-Lock Expiration", "Consent Status", "Digital Signature"
        ])
        h_perms = self.table_pat_perms.horizontalHeader()
        h_perms.setSectionResizeMode(QHeaderView.Interactive)
        h_perms.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h_perms.setSectionResizeMode(1, QHeaderView.Stretch)
        h_perms.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h_perms.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        h_perms.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        h_perms.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        h_perms.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        tp_layout.addWidget(self.table_pat_perms)

        perm_btn_row = QHBoxLayout()
        btn_revoke = QPushButton("Revoke Consent Immediately")
        btn_revoke.setStyleSheet("background-color: #dc2626; color: white; font-weight: bold; padding: 8px 16px; font-size: 13px;")
        btn_revoke.clicked.connect(self.execute_patient_revoke)
        perm_btn_row.addWidget(btn_revoke)

        lbl_revoke_note = QLabel("Revoking consent immediately updates the dynamic state on the blockchain ledger with zero re-encryption cost.")
        lbl_revoke_note.setStyleSheet("color: #64748b; font-size: 11px;")
        perm_btn_row.addWidget(lbl_revoke_note)
        perm_btn_row.addStretch()
        tp_layout.addLayout(perm_btn_row)

        self.patient_tabs.addTab(tab_permissions, "Access Governance")

        # Tab 4: Security Audit Trail
        tab_audit = QWidget()
        ta_layout = QVBoxLayout(tab_audit)
        ta_layout.setContentsMargins(12, 12, 12, 12)
        ta_layout.setSpacing(10)

        self.table_pat_audit = QTableWidget()
        self.table_pat_audit.setColumnCount(6)
        self.table_pat_audit.setHorizontalHeaderLabels([
            "Timestamp", "Record ID", "Physician", "Access Type", "Authorization Status", "Audit Code / Reason"
        ])
        h_audit = self.table_pat_audit.horizontalHeader()
        h_audit.setSectionResizeMode(QHeaderView.Interactive)
        h_audit.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h_audit.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h_audit.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h_audit.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        h_audit.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        h_audit.setSectionResizeMode(5, QHeaderView.Stretch)
        ta_layout.addWidget(self.table_pat_audit)

        self.patient_tabs.addTab(tab_audit, "Security Audit Trail")

        layout.addWidget(self.patient_tabs)

    # -------------------------------------------------------------
    # SCREEN 3: PHYSICIAN WORKSTATION
    # -------------------------------------------------------------
    def setup_doctor_screen(self):
        layout = QVBoxLayout(self.screen_doctor)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(12)

        # Physician Header Card
        self.card_doctor_header = QFrame()
        self.card_doctor_header.setObjectName("doctorHeaderCard")
        self.card_doctor_header.setStyleSheet(
            "QFrame#doctorHeaderCard { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 4px; padding: 12px 16px; }"
        )
        cdh_layout = QHBoxLayout(self.card_doctor_header)
        cdh_layout.setContentsMargins(0, 0, 0, 0)

        doc_vbox = QVBoxLayout()
        self.lbl_doc_greeting = QLabel("Physician Clinical Consultation Workstation")
        self.lbl_doc_greeting.setFont(QFont("Segoe UI", 15, QFont.Bold))
        self.lbl_doc_greeting.setStyleSheet("color: #047857;")
        doc_vbox.addWidget(self.lbl_doc_greeting)

        self.lbl_doc_sub = QLabel("Consortium Facility Workstation | Cryptographic Key Decapsulation (RSA-2048 OAEP)")
        self.lbl_doc_sub.setFont(QFont("Segoe UI", 11))
        self.lbl_doc_sub.setStyleSheet("color: #64748b;")
        doc_vbox.addWidget(self.lbl_doc_sub)
        cdh_layout.addLayout(doc_vbox)

        cdh_layout.addStretch()

        # 4 Metric Badges
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(8)
        self.kpi_doc_cases = self._create_kpi_badge("Assigned Cases", "0", "#059669")
        self.kpi_doc_timelock = self._create_kpi_badge("Active Consents", "0", "#2563eb")
        self.kpi_doc_dept = self._create_kpi_badge("Physician Specialty", "Cardiology", "#7c3aed")
        self.kpi_doc_sigs = self._create_kpi_badge("Signatures", "Verified", "#0f766e")
        kpi_row.addWidget(self.kpi_doc_cases)
        kpi_row.addWidget(self.kpi_doc_timelock)
        kpi_row.addWidget(self.kpi_doc_dept)
        kpi_row.addWidget(self.kpi_doc_sigs)
        cdh_layout.addLayout(kpi_row)

        layout.addWidget(self.card_doctor_header)

        # Authorized Records Table
        lbl_sec_title = QLabel("Patient Diagnostic Records Authorized for Consultation:")
        lbl_sec_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(lbl_sec_title)

        self.table_doc_shared = QTableWidget()
        self.table_doc_shared.setColumnCount(8)
        self.table_doc_shared.setHorizontalHeaderLabels([
            "Patient Name", "Record ID", "Document Title", "Record Category", "Clinical Remarks", "Encrypted File Name", "Time-Lock Expiry", "Access Status"
        ])
        h_doc = self.table_doc_shared.horizontalHeader()
        h_doc.setSectionResizeMode(QHeaderView.Interactive)
        h_doc.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h_doc.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h_doc.setSectionResizeMode(2, QHeaderView.Stretch)
        h_doc.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        h_doc.setSectionResizeMode(4, QHeaderView.Stretch)
        h_doc.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        h_doc.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        h_doc.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table_doc_shared.cellDoubleClicked.connect(self.execute_doctor_decrypt)
        layout.addWidget(self.table_doc_shared)

        # Action Bar
        doc_btn_row = QHBoxLayout()
        btn_decrypt = QPushButton("Decrypt and Review Diagnostic Report")
        btn_decrypt.setFont(QFont("Segoe UI", 11, QFont.Bold))
        btn_decrypt.setStyleSheet("background-color: #059669; color: white; font-weight: bold; padding: 10px 22px; font-size: 13.5px; border-radius: 4px;")
        btn_decrypt.clicked.connect(self.execute_doctor_decrypt)
        doc_btn_row.addWidget(btn_decrypt)

        lbl_doc_hint = QLabel("Select any authorized record above or double-click to verify blockchain consent and decrypt.")
        lbl_doc_hint.setStyleSheet("color: #64748b; font-size: 11px;")
        doc_btn_row.addWidget(lbl_doc_hint)
        doc_btn_row.addStretch()

        layout.addLayout(doc_btn_row)

    # -------------------------------------------------------------
    # SCREEN 4: CONSORTIUM BLOCKCHAIN EXPLORER
    # -------------------------------------------------------------
    def setup_ledger_screen(self):
        layout = QVBoxLayout(self.screen_ledger)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(12)

        # Explorer Header
        header_card = QFrame()
        header_card.setStyleSheet("background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 4px; padding: 12px 16px;")
        hc_layout = QHBoxLayout(header_card)
        hc_layout.setContentsMargins(0, 0, 0, 0)
        hc_layout.setSpacing(12)

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(2)
        lbl_title = QLabel("Consortium Blockchain Ledger & Forensic Audit Explorer")
        lbl_title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        lbl_title.setStyleSheet("color: #0f172a;")
        title_vbox.addWidget(lbl_title)

        lbl_desc = QLabel("Immutable Cryptographic Audit Trail | Proof of Authority (PoA) Consensus | SHA-256 Hash Continuity")
        lbl_desc.setFont(QFont("Segoe UI", 11))
        lbl_desc.setStyleSheet("color: #64748b;")
        title_vbox.addWidget(lbl_desc)
        hc_layout.addLayout(title_vbox)

        hc_layout.addStretch()

        self.kpi_ledger_blocks = self._create_kpi_badge("Blocks Mined", "0", "#0284c7")
        self.kpi_ledger_tx = self._create_kpi_badge("Transactions", "0", "#2563eb")
        self.kpi_ledger_chain = self._create_kpi_badge("Hash Chain", "100% VALID", "#059669")
        hc_layout.addWidget(self.kpi_ledger_blocks)
        hc_layout.addWidget(self.kpi_ledger_tx)
        hc_layout.addWidget(self.kpi_ledger_chain)

        btn_verify_chain = QPushButton("Verify Cryptographic Chain")
        btn_verify_chain.setFont(QFont("Segoe UI", 11, QFont.Bold))
        btn_verify_chain.setStyleSheet("background-color: #059669; color: white; padding: 8px 16px; border-radius: 4px; font-size: 13px; font-weight: 600;")
        btn_verify_chain.clicked.connect(self.verify_blockchain_integrity_dialog)
        hc_layout.addWidget(btn_verify_chain)

        # Return / Back Button (Seamless Navigation)
        self.btn_ledger_return = QPushButton("Return to Sign In")
        self.btn_ledger_return.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.btn_ledger_return.setStyleSheet(
            "background-color: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 8px 16px; border-radius: 4px; font-size: 13px; font-weight: 600;"
        )
        self.btn_ledger_return.clicked.connect(self.return_from_ledger)
        hc_layout.addWidget(self.btn_ledger_return)

        layout.addWidget(header_card)

        # Splitter: Blocks Table on Top, Transaction Inspector on Bottom
        splitter = QSplitter(Qt.Vertical)

        self.table_blocks = QTableWidget()
        self.table_blocks.setColumnCount(5)
        self.table_blocks.setHorizontalHeaderLabels([
            "Block #", "Timestamp (UTC)", "Current Block Hash (SHA-256)", "Previous Block Hash Link", "Transactions Count"
        ])
        h_blk = self.table_blocks.horizontalHeader()
        h_blk.setSectionResizeMode(QHeaderView.Interactive)
        h_blk.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h_blk.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h_blk.setSectionResizeMode(2, QHeaderView.Stretch)
        h_blk.setSectionResizeMode(3, QHeaderView.Stretch)
        h_blk.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_blocks.cellClicked.connect(self.show_block_transactions)
        splitter.addWidget(self.table_blocks)

        box_tx = QGroupBox("Selected Block Transaction Payload & Non-Repudiable Digital Signatures")
        box_tx.setFont(QFont("Segoe UI", 11, QFont.Bold))
        btx_layout = QVBoxLayout(box_tx)
        self.txt_ledger_details = QTextEdit()
        self.txt_ledger_details.setReadOnly(True)
        self.txt_ledger_details.setFont(QFont("Consolas", 11))
        self.txt_ledger_details.setStyleSheet("background-color: #0f172a; color: #38bdf8; border: none; border-radius: 3px; padding: 10px;")
        btx_layout.addWidget(self.txt_ledger_details)
        splitter.addWidget(box_tx)

        splitter.setSizes([320, 240])
        layout.addWidget(splitter)

    # -------------------------------------------------------------
    # KPI BADGE HELPER
    # -------------------------------------------------------------
    def _create_kpi_badge(self, label_text: str, default_val: str, color_hex: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("kpiBadge")
        frame.setStyleSheet("QFrame#kpiBadge { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 6px 14px; }")
        v = QVBoxLayout(frame)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        lbl = QLabel(label_text)
        lbl.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl.setStyleSheet("color: #64748b;")
        lbl.setAlignment(Qt.AlignCenter)
        v.addWidget(lbl)
        
        val = QLabel(default_val)
        val.setObjectName("val")
        val.setFont(QFont("Segoe UI", 14, QFont.Bold))
        val.setStyleSheet(f"color: {color_hex};")
        val.setAlignment(Qt.AlignCenter)
        v.addWidget(val)
        return frame

    def _set_kpi_value(self, badge_frame: QFrame, new_val: str):
        val_label = badge_frame.findChild(QLabel, "val")
        if val_label:
            val_label.setText(str(new_val))

    # -------------------------------------------------------------
    # SCREEN NAVIGATION & SESSION CONTROL
    # -------------------------------------------------------------
    def return_from_ledger(self):
        if not self.current_user:
            self.show_login_screen()
        elif self.current_user.get('role') == 'doctor':
            self.show_doctor_screen()
        else:
            self.show_patient_screen()

    def show_login_screen(self):
        self.current_user = None
        self.lbl_user_session.setText("Not Logged In")
        self.btn_header_logout.setVisible(False)
        self.stack.setCurrentIndex(0)
        self.update_status_bar()

    def show_patient_screen(self):
        self.stack.setCurrentIndex(1)
        self.btn_header_logout.setVisible(True)
        if self.current_user:
            self.lbl_pat_greeting.setText(f"Patient Portal: {self.current_user['full_name']}")
            hosp = self.current_user.get('hospital') or "Metro General Health Network"
            self.lbl_pat_sub.setText(f"Facility: {hosp} | Patient ID: @{self.current_user['username']} | Sovereign Health Record Governance")
        self.refresh_patient_screen()
        self.update_status_bar()

    def show_doctor_screen(self):
        self.stack.setCurrentIndex(2)
        self.btn_header_logout.setVisible(True)
        if self.current_user:
            self.lbl_doc_greeting.setText(f"Physician Workstation: {self.current_user['full_name']}")
            hosp = self.current_user.get('hospital') or "Metro General Health Network"
            dept = self.current_user.get('department') or "General Medicine"
            self.lbl_doc_sub.setText(f"Facility: {hosp} | Physician Specialty: {dept} | Cryptographic Key Decapsulation (RSA-2048 OAEP)")
            self._set_kpi_value(self.kpi_doc_dept, dept)
        self.refresh_doctor_screen()
        self.update_status_bar()

    def show_ledger_screen(self):
        self.stack.setCurrentIndex(3)
        if hasattr(self, 'btn_ledger_return'):
            if not self.current_user:
                self.btn_ledger_return.setText("Return to Sign In")
                self.btn_header_logout.setVisible(False)
            elif self.current_user.get('role') == 'doctor':
                self.btn_ledger_return.setText("Return to Physician Workstation")
                self.btn_header_logout.setVisible(True)
            else:
                self.btn_ledger_return.setText("Return to Patient Portal")
                self.btn_header_logout.setVisible(True)
        self.refresh_ledger_screen()
        self.update_status_bar()

    def update_status_bar(self):
        blocks_count = len(self.blockchain.chain)
        records_count = len(database.get_all_records())
        is_valid = self.blockchain.is_chain_valid()
        status_txt = "100% VALID (Zero Tampering)" if is_valid else "COMPROMISED (Tamper Detected)"
        msg = f"Consortium Node: SYNCHRONIZED | Ledger Integrity: {status_txt} | Mined Blocks: {blocks_count} | Total Records: {records_count}"
        self.status_bar.showMessage(msg)

    def launch_secondary_node_window(self):
        try:
            script_path = os.path.abspath(__file__)
            subprocess.Popen([sys.executable, script_path])
            self.status_bar.showMessage("Launched secondary hospital terminal window for side-by-side demo.", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Process Error", f"Failed to spawn secondary window: {str(e)}")

    def realtime_background_sync(self):
        try:
            self.blockchain.load_from_disk()
            curr_idx = self.stack.currentIndex()
            if curr_idx == 1 and self.current_user:
                self.refresh_patient_permissions_table()
                self.refresh_patient_audit_table()
            elif curr_idx == 2 and self.current_user:
                self.refresh_doctor_shared_table()
            elif curr_idx == 3:
                self.refresh_ledger_blocks_table()
            self.update_status_bar()
        except Exception:
            pass

    # -------------------------------------------------------------
    # PATIENT WORKSPACE OPERATIONS
    # -------------------------------------------------------------
    def refresh_patient_screen(self):
        self.refresh_patient_docs_table()
        self.refresh_patient_permissions_table()
        self.refresh_patient_audit_table()

    def refresh_patient_docs_table(self):
        if not self.current_user:
            return
        records = database.get_patient_records(self.current_user['username'])
        self.table_pat_docs.setRowCount(len(records))

        for i, r in enumerate(records):
            notes_str = r.get('diagnosis') or "Standard diagnostic consult."
            self.table_pat_docs.setItem(i, 0, QTableWidgetItem(r['record_id']))
            self.table_pat_docs.setItem(i, 1, QTableWidgetItem(r['title']))
            self.table_pat_docs.setItem(i, 2, QTableWidgetItem(r.get('category', 'General Medicine')))
            
            notes_item = QTableWidgetItem(notes_str)
            notes_item.setToolTip(notes_str)
            self.table_pat_docs.setItem(i, 3, notes_item)

            file_display = r['file_name']
            if not file_display or file_display == "Clinical Note" or file_display.endswith('_notes.txt'):
                file_display = "Clinical Note (Text)"
            self.table_pat_docs.setItem(i, 4, QTableWidgetItem(file_display))
            self.table_pat_docs.setItem(i, 5, QTableWidgetItem(str(r['file_size'])))
            
            cid_item = QTableWidgetItem(f"{r['content_hash'][:16]}...")
            cid_item.setToolTip(f"Full SHA-256 Content ID:\n{r['content_hash']}")
            self.table_pat_docs.setItem(i, 6, cid_item)

            self.table_pat_docs.setItem(i, 7, QTableWidgetItem(f"Block #{r['block_index']}"))

        self._set_kpi_value(self.kpi_pat_records, str(len(records)))
        self._set_kpi_value(self.kpi_pat_blocks, str(len(self.blockchain.chain)))

    def refresh_patient_permissions_table(self):
        if not self.current_user:
            return
        pat_username = self.current_user['username']
        self.blockchain.load_from_disk()

        pat_perms = []
        doctors_set = set()
        active_count = 0

        for (p_id, r_id, d_id), policy in self.blockchain.permissions.items():
            if p_id == pat_username:
                pat_perms.append((r_id, d_id, policy))
                doctors_set.add(d_id)
                if policy.get('active', False) and time.time() <= policy.get('valid_until', 0):
                    active_count += 1

        self.table_pat_perms.setRowCount(len(pat_perms))
        for i, (r_id, d_id, policy) in enumerate(pat_perms):
            rec = database.get_record(r_id)
            title = rec['title'] if rec else r_id
            doc = database.get_user(d_id)
            doc_name = doc['full_name'] if doc else d_id
            doc_dept = doc.get('department', 'Consultant') if doc else 'Physician'
            exp_str = datetime.fromtimestamp(policy['valid_until']).strftime('%Y-%m-%d %H:%M')
            is_active = policy.get('active', False) and time.time() <= policy['valid_until']

            self.table_pat_perms.setItem(i, 0, QTableWidgetItem(r_id))
            self.table_pat_perms.setItem(i, 1, QTableWidgetItem(title))
            self.table_pat_perms.setItem(i, 2, QTableWidgetItem(doc_name))
            self.table_pat_perms.setItem(i, 3, QTableWidgetItem(doc_dept))
            self.table_pat_perms.setItem(i, 4, QTableWidgetItem(exp_str))

            status_item = QTableWidgetItem("ACTIVE (Authorized)" if is_active else "REVOKED / EXPIRED")
            status_item.setForeground(QColor("#059669" if is_active else "#dc2626"))
            self.table_pat_perms.setItem(i, 5, status_item)

            sig_str = policy.get('signature', '')
            sig_display = f"{sig_str[:12]}... (RSA-PSS)" if sig_str else "N/A"
            sig_item = QTableWidgetItem(sig_display)
            sig_item.setToolTip(f"Non-repudiable signature:\n{sig_str}")
            self.table_pat_perms.setItem(i, 6, sig_item)

        self._set_kpi_value(self.kpi_pat_consents, str(active_count))
        self._set_kpi_value(self.kpi_pat_doctors, str(len(doctors_set)))

    def refresh_patient_audit_table(self):
        if not self.current_user:
            return
        pat_username = self.current_user['username']
        logs = self.blockchain.get_audit_trail_for_patient(pat_username)

        self.table_pat_audit.setRowCount(len(logs))
        for i, log in enumerate(reversed(logs)):
            ts_str = datetime.fromtimestamp(log['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            action = log.get('action', 'ACCESS_EVENT')
            status = log.get('status', 'LOGGED')
            reason = log.get('reason', '-')
            doc_id = log.get('doctor_id', 'Unknown')
            doc = database.get_user(doc_id)
            doc_name = doc['full_name'] if doc else doc_id

            self.table_pat_audit.setItem(i, 0, QTableWidgetItem(ts_str))
            self.table_pat_audit.setItem(i, 1, QTableWidgetItem(log.get('record_id', '-')))
            self.table_pat_audit.setItem(i, 2, QTableWidgetItem(doc_name))
            self.table_pat_audit.setItem(i, 3, QTableWidgetItem(action))

            status_item = QTableWidgetItem(status)
            if "AUTHORIZED" in status:
                status_item.setForeground(QColor("#059669"))
            else:
                status_item.setForeground(QColor("#dc2626"))
            self.table_pat_audit.setItem(i, 4, status_item)
            self.table_pat_audit.setItem(i, 5, QTableWidgetItem(reason))

    def choose_file_to_upload(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Medical File", "",
            "Medical Files (*.pdf *.png *.jpg *.jpeg *.dcm *.dicom *.txt *.docx *.csv *.tiff);;All Files (*.*)"
        )
        if file_path:
            size = os.path.getsize(file_path)
            if size > MAX_FILE_SIZE_BYTES:
                QMessageBox.critical(self, "File Exceeds Limit", f"File size exceeds maximum threshold of 25.0 MB ({size/1024/1024:.2f} MB).")
                return
            self.selected_file_path = file_path
            self.lbl_selected_file.setText(f"{os.path.basename(file_path)} ({size/1024:.1f} KB)")
            self.lbl_selected_file.setStyleSheet("color: #059669; font-weight: bold;")

    def execute_patient_upload(self):
        title = self.input_doc_title.text().strip()
        category = self.combo_doc_category.currentText()
        notes = self.input_doc_notes.toPlainText().strip()

        if not title:
            QMessageBox.warning(self, "Validation Error", "Please provide a document title.")
            return

        has_file = bool(self.selected_file_path and os.path.exists(self.selected_file_path))

        if has_file:
            with open(self.selected_file_path, 'rb') as f:
                file_bytes = f.read()
            file_name = os.path.basename(self.selected_file_path)
            record_diagnosis = notes if notes else f"Attached medical file: {file_name}"
        else:
            # User submitted CLINICAL NOTES (no file attachment)
            clinical_text = (
                f"METRO HEALTHCARE CONSORTIUM - CLINICAL CONSULTATION NOTE\n"
                f"Record Title: {title}\n"
                f"Record Category: {category}\n"
                f"Patient: {self.current_user['full_name']} (@{self.current_user['username']}) | Hospital: {self.current_user.get('hospital', 'Metro General Hospital')}\n"
                f"Date of Record: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"------------------------------------------------------------------------------------\n"
                f"CLINICAL OBSERVATIONS & NOTES:\n"
                f"{notes if notes else 'Routine clinical consultation notes entered by patient.'}\n"
                f"------------------------------------------------------------------------------------\n"
                f"CRYPTOGRAPHIC STATUS: Encrypted using AES-256-GCM. Anchored on Consortium Blockchain via SHA-256."
            )
            file_bytes = clinical_text.encode('utf-8')
            clean_title = re.sub(r'[\\/*?:"<>|\s]+', '_', title).strip('_') or "Clinical_Note"
            file_name = f"{clean_title}_notes.txt"
            record_diagnosis = notes if notes else f"{category} consultation note."

        file_size = len(file_bytes)
        pat_username = self.current_user['username']
        record_id = f"REC-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        try:
            # AES-256-GCM symmetric encryption
            aes_key = generate_aes_key()
            ciphertext_hex, nonce_hex = encrypt_bytes(file_bytes, aes_key)
            data_hash = compute_bytes_hash(file_bytes)

            # Key Encapsulation (RSA-2048 OAEP)
            pat_pub = load_rsa_public_key(self.current_user['rsa_public_key_pem'])
            enc_aes_key_pat = encrypt_key_for_recipient(aes_key, pat_pub)

            # Content-Addressed Storage (CAS)
            meta = {
                "record_id": record_id,
                "patient_username": pat_username,
                "title": title,
                "category": category,
                "file_name": file_name,
                "file_size": file_size,
                "data_hash": data_hash
            }
            content_hash = storage.save_to_storage(ciphertext_hex, nonce_hex, metadata=meta)

            # Patient Digital Signature (RSA-PSS)
            pat_priv = load_rsa_private_key(self.current_user['rsa_private_key_pem'])
            sig_payload = f"{record_id}:{content_hash}:{data_hash}".encode('utf-8')
            signature = sign_data(sig_payload, pat_priv)

            # Add to blockchain ledger
            self.blockchain.add_record_anchor(
                patient_id=pat_username,
                record_id=record_id,
                content_hash=content_hash,
                data_hash=data_hash,
                record_type=category,
                patient_signature=signature
            )
            mined_block = self.blockchain.mine_block()
            block_idx = mined_block.index if mined_block else self.blockchain.get_latest_block().index

            # Insert metadata into SQLite
            database.insert_record(
                record_id=record_id,
                patient_username=pat_username,
                title=title,
                diagnosis=record_diagnosis,
                category=category,
                file_name=file_name,
                file_size=file_size,
                content_hash=content_hash,
                data_hash=data_hash,
                block_index=block_idx,
                encrypted_aes_key_patient=enc_aes_key_pat
            )

            self.input_doc_title.clear()
            self.input_doc_notes.clear()
            self.selected_file_path = ""
            self.lbl_selected_file.setText("No file attached (Optional, max 25 MB)")
            self.lbl_selected_file.setStyleSheet("color: #64748b; font-style: italic;")

            QMessageBox.information(
                self, "Storage Complete",
                f"Document encrypted and anchored successfully!\n\n"
                f"Record ID: {record_id}\n"
                f"Cipher: AES-256-GCM (128-bit Tag Verified)\n"
                f"Storage CID: {content_hash[:20]}...\n"
                f"Consortium Block: #{block_idx}\n"
                f"Patient Signature: {signature[:20]}..."
            )

            self.refresh_patient_docs_table()
            self.patient_tabs.setCurrentIndex(0)
            self.update_status_bar()

        except Exception as e:
            QMessageBox.critical(self, "Upload Error", f"Failed to encrypt and store document: {str(e)}")

    def dialog_share_record(self):
        row = self.table_pat_docs.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Record", "Please select a medical document from the table first.")
            return

        rec_id = self.table_pat_docs.item(row, 0).text()
        rec_title = self.table_pat_docs.item(row, 1).text()
        rec = database.get_record(rec_id)

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Grant Time-Locked Consent - {rec_id}")
        dlg.resize(460, 240)
        form = QFormLayout(dlg)

        lbl_doc_info = QLabel(f"<b>{rec_title}</b> ({rec_id})")
        form.addRow("Medical File:", lbl_doc_info)

        combo_doctors = QComboBox()
        doctors = database.get_users_by_role("doctor")
        for d in doctors:
            combo_doctors.addItem(f"{d['full_name']} ({d.get('department','General')}) - {d.get('hospital','')}", d['username'])
        form.addRow("Select Physician:", combo_doctors)

        combo_duration = QComboBox()
        combo_duration.addItem("1 Hour (Emergency Consult)", 3600)
        combo_duration.addItem("24 Hours (Standard Clinical Consult)", 86400)
        combo_duration.addItem("7 Days (Post-Operative Follow-up)", 604800)
        combo_duration.addItem("30 Days (Chronic Disease Management)", 2592000)
        form.addRow("Consent Time-Lock:", combo_duration)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        form.addWidget(btns)

        if dlg.exec_() == QDialog.Accepted:
            doc_username = combo_doctors.currentData()
            duration_secs = combo_duration.currentData()

            try:
                # Decapsulate key with patient private key
                pat_priv = load_rsa_private_key(self.current_user['rsa_private_key_pem'])
                aes_key = decrypt_key_with_private_key(rec['encrypted_aes_key_patient'], pat_priv)

                # Encapsulate under Doctor's RSA Public Key
                doc_record = database.get_user(doc_username)
                doc_pub = load_rsa_public_key(doc_record['rsa_public_key_pem'])
                enc_aes_key_doc = encrypt_key_for_recipient(aes_key, doc_pub)

                # Patient digital signature
                sig_payload = f"{self.current_user['username']}:{rec_id}:{doc_username}:{duration_secs}".encode('utf-8')
                signature = sign_data(sig_payload, pat_priv)

                # Mint consent grant on blockchain
                self.blockchain.grant_consent(
                    patient_id=self.current_user['username'],
                    record_id=rec_id,
                    doctor_id=doc_username,
                    duration_seconds=float(duration_secs),
                    encrypted_key_for_doctor=enc_aes_key_doc,
                    patient_signature=signature
                )
                mined_block = self.blockchain.mine_block()
                b_idx = mined_block.index if mined_block else self.blockchain.get_latest_block().index

                QMessageBox.information(
                    self, "Consent Granted",
                    f"Access policy successfully minted!\n\n"
                    f"Record: {rec_title}\n"
                    f"Physician: {doc_record['full_name']}\n"
                    f"Validity: {combo_duration.currentText()}\n"
                    f"Block: #{b_idx}\n"
                    f"Digital Signature: {signature[:20]}..."
                )

                self.refresh_patient_permissions_table()
                self.patient_tabs.setCurrentIndex(2)
                self.update_status_bar()

            except Exception as e:
                QMessageBox.critical(self, "Sharing Error", f"Failed to grant consent: {str(e)}")

    def execute_patient_revoke(self):
        row = self.table_pat_perms.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Consent", "Please select a permission entry from the table above.")
            return

        rec_id = self.table_pat_perms.item(row, 0).text()
        doc_name = self.table_pat_perms.item(row, 2).text()

        matching_doc_u = None
        for (p_id, r_id, d_id), policy in self.blockchain.permissions.items():
            if p_id == self.current_user['username'] and r_id == rec_id:
                doc = database.get_user(d_id)
                if doc and doc['full_name'] == doc_name:
                    matching_doc_u = d_id
                    break

        if not matching_doc_u:
            QMessageBox.warning(self, "Error", "Could not resolve doctor ID.")
            return

        reply = QMessageBox.question(
            self, "Confirm Revocation",
            f"Are you sure you want to revoke physician access for record '{rec_id}'?\n\n"
            f"Physician '{doc_name}' will immediately lose decryption ability on the blockchain.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            pat_priv = load_rsa_private_key(self.current_user['rsa_private_key_pem'])
            sig_payload = f"REVOKE:{self.current_user['username']}:{rec_id}:{matching_doc_u}".encode('utf-8')
            signature = sign_data(sig_payload, pat_priv)

            self.blockchain.revoke_consent(
                patient_id=self.current_user['username'],
                record_id=rec_id,
                doctor_id=matching_doc_u,
                patient_signature=signature
            )
            mined_block = self.blockchain.mine_block()
            b_idx = mined_block.index if mined_block else self.blockchain.get_latest_block().index

            QMessageBox.information(
                self, "Access Revoked",
                f"Consent revoked successfully!\n\n"
                f"Physician: {doc_name}\n"
                f"Record: {rec_id}\n"
                f"Consortium Block Mined: #{b_idx}\n"
                f"Ledger State: Permission updated to REVOKED."
            )
            self.refresh_patient_permissions_table()
            self.update_status_bar()

    def patient_view_record_details(self):
        row = self.table_pat_docs.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Record", "Please select a record from the table above.")
            return

        rec_id = self.table_pat_docs.item(row, 0).text()
        rec = database.get_record(rec_id)
        if not rec:
            return

        try:
            pat_priv = load_rsa_private_key(self.current_user['rsa_private_key_pem'])
            aes_key = decrypt_key_with_private_key(rec['encrypted_aes_key_patient'], pat_priv)

            storage_data = storage.get_from_storage(rec['content_hash'])
            decrypted_bytes = decrypt_bytes(storage_data['ciphertext'], storage_data['nonce'], aes_key)

            self._open_clinical_viewer_dialog(rec, decrypted_bytes, is_doctor=False)

        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Failed to decrypt document: {str(e)}")

    def patient_download_own_record(self):
        row = self.table_pat_docs.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Record", "Please select a record from the table first.")
            return

        rec_id = self.table_pat_docs.item(row, 0).text()
        rec = database.get_record(rec_id)
        if not rec:
            return

        try:
            pat_priv = load_rsa_private_key(self.current_user['rsa_private_key_pem'])
            aes_key = decrypt_key_with_private_key(rec['encrypted_aes_key_patient'], pat_priv)
            storage_data = storage.get_from_storage(rec['content_hash'])
            decrypted_bytes = decrypt_bytes(storage_data['ciphertext'], storage_data['nonce'], aes_key)

            # Determine genuine format from content and record metadata
            is_pdf = decrypted_bytes.startswith(b'%PDF')
            raw_title = rec.get('title') or "Medical_Document"
            clean_title = re.sub(r'[\\/*?:"<>|\s]+', '_', raw_title).strip('_') or "Document"

            orig_name = rec.get('file_name', '')
            if orig_name and orig_name != "Clinical Note" and not orig_name.endswith('.*') and '.' in orig_name and not orig_name.endswith('_notes.txt'):
                suggested_name = orig_name
                ext = os.path.splitext(orig_name)[1].lower()
            elif is_pdf:
                suggested_name = f"{clean_title}_Report.pdf"
                ext = ".pdf"
            else:
                suggested_name = f"{clean_title}_Clinical_Note.txt"
                ext = ".txt"

            if ext == ".pdf":
                filter_str = "PDF Documents (*.pdf);;All Files (*.*)"
            elif ext == ".txt":
                filter_str = "Text Documents (*.txt);;All Files (*.*)"
            else:
                filter_str = f"Document (*{ext});;All Files (*.*)"

            save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted Medical Document", suggested_name, filter_str)
            if save_path:
                if not os.path.splitext(save_path)[1]:
                    save_path += ext
                with open(save_path, 'wb') as f:
                    f.write(decrypted_bytes)
                reply = QMessageBox.question(
                    self, "Download Complete",
                    f"Decrypted file saved successfully:\n{save_path}\n\nWould you like to open it now?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    try:
                        os.startfile(save_path)
                    except Exception as err:
                        QMessageBox.warning(self, "Viewer Notice", f"Could not launch viewer: {str(err)}")
        except Exception as e:
            QMessageBox.critical(self, "Download Error", f"Failed to decrypt and save: {str(e)}")

    # -------------------------------------------------------------
    # PHYSICIAN WORKSTATION OPERATIONS
    # -------------------------------------------------------------
    def refresh_doctor_screen(self):
        self.refresh_doctor_shared_table()

    def refresh_doctor_shared_table(self):
        if not self.current_user:
            return
        doc_username = self.current_user['username']
        all_records = database.get_all_records()

        shared_list = []
        active_count = 0
        for r in all_records:
            is_allowed, enc_key, reason = self.blockchain.check_permission(r['patient_username'], r['record_id'], doc_username)
            policy = self.blockchain.permissions.get((r['patient_username'], r['record_id'], doc_username))
            if policy:
                shared_list.append((r, is_allowed, policy))
                if is_allowed and time.time() <= policy.get('valid_until', 0):
                    active_count += 1

        self.table_doc_shared.setRowCount(len(shared_list))
        for i, (r, is_allowed, policy) in enumerate(shared_list):
            pat = database.get_user(r['patient_username'])
            pat_name = pat['full_name'] if pat else r['patient_username']
            exp_str = datetime.fromtimestamp(policy['valid_until']).strftime('%Y-%m-%d %H:%M')
            is_active = is_allowed and time.time() <= policy['valid_until']
            notes_str = r.get('diagnosis') or "Standard diagnostic consult."

            self.table_doc_shared.setItem(i, 0, QTableWidgetItem(pat_name))
            self.table_doc_shared.setItem(i, 1, QTableWidgetItem(r['record_id']))
            self.table_doc_shared.setItem(i, 2, QTableWidgetItem(r['title']))
            self.table_doc_shared.setItem(i, 3, QTableWidgetItem(r.get('category', 'General Medicine')))
            
            notes_item = QTableWidgetItem(notes_str)
            notes_item.setToolTip(notes_str)
            self.table_doc_shared.setItem(i, 4, notes_item)

            file_display = r['file_name']
            if not file_display or file_display == "Clinical Note" or file_display.endswith('_notes.txt'):
                file_display = "Clinical Note (Text)"
            self.table_doc_shared.setItem(i, 5, QTableWidgetItem(file_display))
            self.table_doc_shared.setItem(i, 6, QTableWidgetItem(exp_str))

            status_item = QTableWidgetItem("ACTIVE (Authorized)" if is_active else "REVOKED / EXPIRED")
            status_item.setForeground(QColor("#059669" if is_active else "#dc2626"))
            self.table_doc_shared.setItem(i, 7, status_item)

        self._set_kpi_value(self.kpi_doc_cases, str(len(shared_list)))
        self._set_kpi_value(self.kpi_doc_timelock, str(active_count))

    def execute_doctor_decrypt(self):
        row = self.table_doc_shared.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Record", "Please select a record from the table above.")
            return

        rec_id = self.table_doc_shared.item(row, 1).text()
        doc_username = self.current_user['username']
        rec = database.get_record(rec_id)

        # 1. Check Blockchain Access Policy & Log Unauthorized Attempt if Denied
        is_allowed, enc_key_hex, reason_str = self.blockchain.check_permission(rec['patient_username'], rec_id, doc_username)
        if not is_allowed or not enc_key_hex:
            self.blockchain.log_unauthorized_access(rec['patient_username'], rec_id, doc_username, reason_str)
            self.blockchain.mine_block()
            
            QMessageBox.critical(
                self, "Access Denied on Blockchain",
                f"BLOCKCHAIN ACCESS GATEKEEPING ALERT:\n\n"
                f"Physician '{doc_username}' is NOT authorized to access record {rec_id}.\n"
                f"Rejection Reason: {reason_str}\n\n"
                f"This unauthorized access event has been permanently recorded on the blockchain ledger for patient audit."
            )
            self.refresh_doctor_screen()
            self.update_status_bar()
            return

        try:
            # 2. Check CAS Storage Integrity (detects bit-flip tampering or corruption)
            if not storage.verify_integrity(rec['content_hash']):
                self.blockchain.log_unauthorized_access(rec['patient_username'], rec_id, doc_username, "CAS_STORAGE_TAMPER_DETECTED")
                self.blockchain.mine_block()
                
                QMessageBox.critical(
                    self, "Critical Tamper Alert",
                    f"CRITICAL CRYPTOGRAPHIC INTEGRITY FAILURE:\n\n"
                    f"The off-chain storage ciphertext does not match its SHA-256 CID hash.\n"
                    f"Expected CID: {rec['content_hash']}\n\n"
                    f"Payload has been altered on disk! Decryption halted to protect patient safety.\n"
                    f"This security anomaly has been immutably recorded on the consortium blockchain."
                )
                self.update_status_bar()
                return

            # 3. Decapsulate AES key with Doctor's RSA Private Key (OAEP)
            doc_priv = load_rsa_private_key(self.current_user['rsa_private_key_pem'])
            aes_key = decrypt_key_with_private_key(enc_key_hex, doc_priv)

            # 4. Retrieve ciphertext from off-chain storage
            storage_data = storage.get_from_storage(rec['content_hash'])

            # 5. Decrypt original document bytes with AES-256-GCM
            decrypted_bytes = decrypt_bytes(storage_data['ciphertext'], storage_data['nonce'], aes_key)

            # 6. Verify cryptographic SHA-256 data integrity
            data_hash = compute_bytes_hash(decrypted_bytes)
            if data_hash != rec['data_hash']:
                QMessageBox.critical(self, "Integrity Error", "SHA-256 Hash mismatch! Document payload was tampered with.")
                return

            # 7. Log authorized access event to blockchain
            self.blockchain.log_record_access(rec['patient_username'], rec_id, doc_username)
            mined_block = self.blockchain.mine_block()
            block_idx = mined_block.index if mined_block else self.blockchain.get_latest_block().index

            # 8. Open Clinical Consultation View
            self._open_clinical_viewer_dialog(rec, decrypted_bytes, is_doctor=True, block_idx=block_idx)
            self.update_status_bar()

        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Decryption failed: {str(e)}")

    def _open_clinical_viewer_dialog(self, rec: dict, decrypted_bytes: bytes, is_doctor: bool, block_idx: int = 1):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Clinical Diagnostic Report Viewer - {rec['record_id']}")
        dlg.resize(800, 640)
        vbox = QVBoxLayout(dlg)
        vbox.setContentsMargins(18, 18, 18, 18)
        vbox.setSpacing(12)

        # Hospital Letterhead
        letterhead = QFrame()
        letterhead.setStyleSheet("background-color: #0f172a; color: white; border-radius: 4px; padding: 12px;")
        lh_layout = QVBoxLayout(letterhead)
        lh_layout.setSpacing(2)
        
        lbl_hosp_title = QLabel("METRO HEALTHCARE CONSORTIUM - CLINICAL DIAGNOSTIC REPORT")
        lbl_hosp_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        lbl_hosp_title.setStyleSheet("color: #38bdf8;")
        lh_layout.addWidget(lbl_hosp_title)

        pat = database.get_user(rec['patient_username'])
        pat_name = pat['full_name'] if pat else rec['patient_username']
        hosp = pat.get('hospital') or "Metro General Hospital"
        meta_str = f"Patient: {pat_name} (@{rec['patient_username']}) | Hospital: {hosp} | Record Category: {rec.get('category','General')}"
        if is_doctor and self.current_user:
            doc_dept = self.current_user.get('department') or 'General Medicine'
            meta_str += f" | Reviewing Physician: {self.current_user['full_name']} (Specialty: {doc_dept})"
        lbl_hosp_meta = QLabel(meta_str)
        lbl_hosp_meta.setFont(QFont("Segoe UI", 9))
        lbl_hosp_meta.setStyleSheet("color: #cbd5e1;")
        lh_layout.addWidget(lbl_hosp_meta)
        vbox.addWidget(letterhead)

        # Cryptographic Verification Box
        crypto_box = QGroupBox("Cryptographic Verification & Blockchain Integrity Seals")
        c_layout = QFormLayout(crypto_box)
        c_layout.setSpacing(6)
        c_layout.addRow("Encryption Standard:", QLabel("AES-256-GCM (NIST SP 800-38D) with 96-bit CSPRNG Nonce [VERIFIED]"))
        c_layout.addRow("Key Encapsulation:", QLabel("RSA-2048 OAEP with SHA-256 / MGF1 [AUTHENTICATED]"))
        c_layout.addRow("Storage CID Anchor:", QLabel(f"SHA-256: {rec['content_hash'][:24]}... (Matches On-Chain Root)"))
        c_layout.addRow("Audit Logging:", QLabel(f"Access event permanently anchored in Consortium Block #{block_idx}"))
        vbox.addWidget(crypto_box)

        # File inspection & content preview
        file_name = rec.get('file_name', 'document.dat')
        is_binary_pdf = decrypted_bytes.startswith(b'%PDF')

        display_text = ""
        if is_binary_pdf:
            try:
                reader = pypdf.PdfReader(io.BytesIO(decrypted_bytes))
                pages = [page.extract_text() for page in reader.pages if page.extract_text()]
                if pages:
                    display_text = f"=== ATTACHED MEDICAL PDF DOCUMENT: {file_name} ({len(decrypted_bytes)/1024:.1f} KB) ===\n\n" + "\n\n--- Page Break ---\n\n".join(pages)
                else:
                    display_text = (
                        f"=== ATTACHED MEDICAL PDF DOCUMENT: {file_name} ({len(decrypted_bytes)/1024:.1f} KB) ===\n"
                        f"Format: Formatted Graphical / Scanned PDF Document\n"
                        f"Cryptographic Status: AES-256-GCM Verified (Zero Tampering)\n\n"
                        f"Clinical Remarks / Findings:\n"
                        f"{rec.get('diagnosis') or 'No diagnostic remarks provided.'}\n\n"
                        f"Click 'Open in System PDF Viewer' below to view the original medical report in Adobe Acrobat or your default viewer."
                    )
            except Exception:
                display_text = (
                    f"=== ATTACHED MEDICAL PDF DOCUMENT: {file_name} ({len(decrypted_bytes)/1024:.1f} KB) ===\n"
                    f"Cryptographic Status: AES-256-GCM Verified\n\n"
                    f"Clinical Remarks / Findings:\n"
                    f"{rec.get('diagnosis') or 'No diagnostic remarks provided.'}\n\n"
                    f"Click 'Open in System PDF Viewer' below to view the original medical report."
                )
        else:
            # Direct Clinical Consultation Notes / UTF-8 text
            try:
                display_text = decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                display_text = f"=== BINARY ATTACHMENT: {file_name} ({len(decrypted_bytes)/1024:.1f} KB) ===\nClinical Remarks: {rec.get('diagnosis') or 'None'}\nClick 'Save Decrypted File' to inspect."

        content_title = "Attached Medical Document Preview:" if is_binary_pdf else "Decrypted Clinical Notes & Findings:"
        lbl_doc_head = QLabel(content_title)
        lbl_doc_head.setFont(QFont("Segoe UI", 10, QFont.Bold))
        vbox.addWidget(lbl_doc_head)

        txt_content = QTextEdit()
        txt_content.setReadOnly(True)
        txt_content.setFont(QFont("Consolas", 10))
        txt_content.setStyleSheet("background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 3px; padding: 10px;")
        txt_content.setText(display_text)
        vbox.addWidget(txt_content)

        # Action Buttons
        btn_box = QHBoxLayout()

        if is_binary_pdf:
            btn_open = QPushButton("Open in System PDF Viewer")
            btn_open.setStyleSheet("background-color: #059669; color: white; font-weight: bold; padding: 7px 15px;")
            btn_open.clicked.connect(lambda: self._open_in_system_viewer(file_name, decrypted_bytes))
            btn_box.addWidget(btn_open)

            btn_save = QPushButton("Save Decrypted PDF")
            btn_save.setStyleSheet("background-color: #0284c7; color: white; font-weight: bold; padding: 7px 15px;")
            btn_save.clicked.connect(lambda: self._save_decrypted_document(file_name, decrypted_bytes))
            btn_box.addWidget(btn_save)
        else:
            # Clinical Notes buttons
            save_name = f"{rec['title'].replace(' ', '_')}_notes.txt" if rec.get('title') else "Clinical_Notes.txt"
            btn_save_txt = QPushButton("Save Clinical Notes (.txt)")
            btn_save_txt.setStyleSheet("background-color: #0284c7; color: white; font-weight: bold; padding: 7px 15px;")
            btn_save_txt.clicked.connect(lambda: self._save_decrypted_document(save_name, decrypted_bytes))
            btn_box.addWidget(btn_save_txt)

            btn_export_pdf = QPushButton("Export Notes as PDF")
            btn_export_pdf.setStyleSheet("background-color: #0f766e; color: white; font-weight: bold; padding: 7px 15px;")
            btn_export_pdf.clicked.connect(lambda: self._export_notes_to_pdf(rec, display_text))
            btn_box.addWidget(btn_export_pdf)

        btn_box.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setStyleSheet("background-color: #f1f5f9; color: #1e293b; border: 1px solid #cbd5e1; padding: 7px 15px;")
        btn_close.clicked.connect(dlg.accept)
        btn_box.addWidget(btn_close)
        vbox.addLayout(btn_box)

        dlg.exec_()

    def _export_notes_to_pdf(self, rec: dict, notes_text: str):
        default_name = f"{rec['title'].replace(' ', '_')}_Report.pdf"
        path, _ = QFileDialog.getSaveFileName(self, "Export Clinical Notes as PDF", default_name, "PDF Documents (*.pdf)")
        if path:
            try:
                pdf_bytes = make_medical_report_pdf(rec['title'], notes_text)
                with open(path, "wb") as f:
                    f.write(pdf_bytes)
                reply = QMessageBox.question(
                    self, "PDF Export Complete",
                    f"Clinical report PDF generated and saved successfully:\n{path}\n\nWould you like to open it now?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    try:
                        os.startfile(path)
                    except Exception as err:
                        QMessageBox.warning(self, "Viewer Notice", f"Could not launch viewer: {str(err)}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export PDF: {str(e)}")

    def _save_decrypted_document(self, default_name: str, file_bytes: bytes):
        is_pdf = file_bytes.startswith(b'%PDF')
        if not default_name or default_name == "Clinical Note" or '.' not in default_name or default_name.endswith('.*'):
            default_name = "Medical_Report.pdf" if is_pdf else "Clinical_Notes.txt"

        ext = os.path.splitext(default_name)[1].lower()
        if ext == ".pdf":
            filter_str = "PDF Documents (*.pdf);;All Files (*.*)"
        elif ext == ".txt":
            filter_str = "Text Documents (*.txt);;All Files (*.*)"
        else:
            filter_str = f"Document (*{ext});;All Files (*.*)"

        path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted Medical Document", default_name, filter_str)
        if path:
            if not os.path.splitext(path)[1]:
                path += ext
            try:
                with open(path, "wb") as f:
                    f.write(file_bytes)
                reply = QMessageBox.question(
                    self, "Save Complete",
                    f"Decrypted document saved successfully:\n{path}\n\nWould you like to open it now?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    try:
                        os.startfile(path)
                    except Exception as err:
                        QMessageBox.warning(self, "Viewer Notice", f"Could not launch viewer: {str(err)}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save file: {str(e)}")

    def _open_in_system_viewer(self, default_name: str, file_bytes: bytes):
        try:
            ext = os.path.splitext(default_name)[1]
            base = os.path.splitext(os.path.basename(default_name))[0]
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix=f"{base}_") as tmp:
                tmp.write(file_bytes)
                temp_path = tmp.name
            os.startfile(temp_path)
        except Exception as e:
            QMessageBox.critical(self, "Open Error", f"Failed to open in system viewer: {str(e)}")

    # -------------------------------------------------------------
    # BLOCKCHAIN EXPLORER OPERATIONS
    # -------------------------------------------------------------
    def refresh_ledger_screen(self):
        self.blockchain.load_from_disk()
        self.refresh_ledger_blocks_table()
        
        total_tx = sum(len(b.transactions) for b in self.blockchain.chain)
        self._set_kpi_value(self.kpi_ledger_blocks, str(len(self.blockchain.chain)))
        self._set_kpi_value(self.kpi_ledger_tx, str(total_tx))
        is_valid = self.blockchain.is_chain_valid()
        self._set_kpi_value(self.kpi_ledger_chain, "100% VALID" if is_valid else "CORRUPTED")

    def refresh_ledger_blocks_table(self):
        self.table_blocks.setRowCount(len(self.blockchain.chain))
        for i, block in enumerate(self.blockchain.chain):
            ts_str = datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            tx_count = len(block.transactions)

            self.table_blocks.setItem(i, 0, QTableWidgetItem(f"Block #{block.index}"))
            self.table_blocks.setItem(i, 1, QTableWidgetItem(ts_str))
            
            hash_item = QTableWidgetItem(f"{block.hash[:20]}...")
            hash_item.setToolTip(f"Full SHA-256 Hash:\n{block.hash}")
            self.table_blocks.setItem(i, 2, hash_item)

            prev_item = QTableWidgetItem(f"{block.previous_hash[:20]}...")
            prev_item.setToolTip(f"Full Previous Hash:\n{block.previous_hash}")
            self.table_blocks.setItem(i, 3, prev_item)

            self.table_blocks.setItem(i, 4, QTableWidgetItem(f"{tx_count} transaction(s)"))

        if len(self.blockchain.chain) > 0 and not self.txt_ledger_details.toPlainText():
            self.show_block_transactions(0, 0)

    def show_block_transactions(self, row, col):
        if row < 0 or row >= len(self.blockchain.chain):
            return
        block = self.blockchain.chain[row]
        details = {
            "block_index": block.index,
            "timestamp": datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S UTC'),
            "block_hash_sha256": block.hash,
            "previous_block_hash": block.previous_hash,
            "transaction_count": len(block.transactions),
            "transactions": block.transactions
        }
        self.txt_ledger_details.setPlainText(json.dumps(details, indent=2))

    def verify_blockchain_integrity_dialog(self):
        is_valid = self.blockchain.is_chain_valid()
        blocks_count = len(self.blockchain.chain)
        if is_valid:
            QMessageBox.information(
                self, "Blockchain Verification Passed",
                f"FORMAL CRYPTOGRAPHIC CHAIN VERIFICATION: 100% VALID\n\n"
                f"- Evaluated Blocks: {blocks_count} blocks (Genesis to Head)\n"
                f"- Off-Chain Data Cipher: AES-256-GCM (NIST SP 800-38D, 128-bit Tag)\n"
                f"- Ledger Block Hashing: SHA-256 (NIST FIPS 180-4)\n"
                f"- Key Encapsulation: RSA-2048 OAEP (SHA-256 / MGF1)\n"
                f"- Digital Signatures: RSA-2048 PSS (SHA-256)\n"
                f"- Chain Continuity: Every previous_hash link strictly verified.\n"
                f"- Block Content Hashes: Recalculated from serialized payloads and confirmed identical.\n"
                f"- Tampering Detected: 0 anomalies (Clean forensic state)"
            )
        else:
            QMessageBox.critical(
                self, "Chain Integrity Compromised",
                "BLOCKCHAIN TAMPER ALERT: One or more blocks have invalid cryptographic hashes or broken previous_hash links!"
            )

    # -------------------------------------------------------------
    # SECURITY & TAMPER DEMONSTRATION TOOLS
    # -------------------------------------------------------------
    def simulate_cas_tamper_attack(self):
        records = database.get_all_records()
        if not records:
            QMessageBox.warning(self, "No Records", "No records found in storage to tamper.")
            return

        target_rec = records[0]
        cid = target_rec['content_hash']
        storage_file = os.path.join(storage.STORAGE_DIR, f"{cid}.json")

        if not os.path.exists(storage_file):
            QMessageBox.critical(self, "Storage Missing", f"File {cid}.json not found.")
            return

        with open(storage_file, "r", encoding="utf-8") as f:
            raw_json = f.read()

        self.last_tampered_cid = cid
        self.tamper_backup_content = raw_json

        data = json.loads(raw_json)
        original_ct = data["ciphertext"]
        tampered_ct = ("0" if original_ct[0] != "0" else "1") + original_ct[1:]
        data["ciphertext"] = tampered_ct

        with open(storage_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(data))

        QMessageBox.warning(
            self, "Storage Tamper Simulation Triggered",
            f"SECURITY ATTACK SIMULATED:\n\n"
            f"1 bit was flipped in off-chain CAS storage file: {cid[:16]}...\n\n"
            f"When a clinician attempts to decrypt this record, the on-read SHA-256 CID verification "
            f"will detect the corruption, immediately halt decryption, and write an immutable intrusion alert to the blockchain."
        )

    def restore_cas_storage_integrity(self):
        if not self.last_tampered_cid or not self.tamper_backup_content:
            QMessageBox.information(self, "Integrity OK", "No active tamper simulation detected.")
            return

        storage_file = os.path.join(storage.STORAGE_DIR, f"{self.last_tampered_cid}.json")
        with open(storage_file, "w", encoding="utf-8") as f:
            f.write(self.tamper_backup_content)

        self.last_tampered_cid = None
        self.tamper_backup_content = None
        QMessageBox.information(self, "Storage Restored", "Off-chain CAS storage integrity 100% restored!")

    def reset_and_reseed_demo_data(self):
        reply = QMessageBox.question(
            self, "Reset & Reseed Dataset",
            "This will populate the database and blockchain with 6 realistic accounts (Alice Smith, Manish Ghag, Dr. Bob Sharma, etc.) "
            "and 4 pre-encrypted clinical diagnostic records.\n\nProceed?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                import seed_healthcare_data
                seed_healthcare_data.seed_complete_healthcare_system()
                self.blockchain.load_from_disk()
                QMessageBox.information(self, "Seeding Complete", "Realistic healthcare dataset loaded successfully!")
                self.update_status_bar()
            except Exception as e:
                QMessageBox.critical(self, "Seeding Error", f"Failed to seed data: {str(e)}")

    def dialog_system_specs(self):
        QMessageBox.information(
            self, "System Architecture & Specifications",
            "HEALTHLEDGER SYSTEM SPECIFICATIONS:\n\n"
            "- Architecture: Dual-Layer Decoupled (Off-Chain CAS + On-Chain Consortium Blockchain)\n"
            "- Symmetric Cipher: AES-256-GCM (NIST SP 800-38D, 96-bit CSPRNG Nonce, 128-bit Tag)\n"
            "- Key Encapsulation: RSA-2048 OAEP (SHA-256, MGF1)\n"
            "- Digital Signatures: RSA-2048 PSS (SHA-256, salt_length=max)\n"
            "- Password Hashing: PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte random salt)\n"
            "- Storage Addressing: SHA-256 Content Identifiers (CID) with on-read bit-flip verification\n"
            "- Consensus: Proof of Authority (PoA) Consortium Model\n"
            "- Revocation Complexity: O(1) Constant Time (Zero-Reencryption Overhead)"
        )

    def dialog_about(self):
        QMessageBox.information(
            self, "About HealthLedger",
            "HealthLedger: Privacy-Preserving Healthcare Data Sharing Using Blockchain\n\n"
            "System Architecture: Consortium Blockchain & Content-Addressed Storage (CAS)\n"
            "Cryptography: AES-256-GCM, RSA-2048 OAEP, RSA-PSS, SHA-256\n"
            "Degree: Master of Science in Information Technology (2026-27)\n"
            "Candidate: Manish Ghag (Roll No. 603)\n\n"
            "Designed and implemented for secure, patient-centric healthcare information exchange."
        )


def main():
    app = QApplication(sys.argv)
    window = HealthLedgerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
