# HealthLedger: Privacy-Preserving Healthcare Data Sharing Using Blockchain

**M.Sc. Information Technology (M.Sc. IT) Research Project & System Implementation**  
**Course Code:** RPSRPIT0605 | **Semester:** III | **Academic Year:** 2026–27  
**Department of Computer Science & Information Technology**  
**S.P. Mandali’s Ramnarain Ruia Autonomous College, Matunga, Mumbai - 400019**  
**Internal Guide:** Mahavir Advaya  
**Submitted By:** Manish Ghag (Roll No. 603)  

---

## 1. Overview

HealthLedger is an end-to-end, privacy-preserving healthcare information exchange platform. It resolves the core trilemma of medical data sharing—**confidentiality**, **inter-institutional accessibility**, and **storage scalability**—by combining:

1. **Client-Side Authenticated Hybrid Cryptography**:
   - High-throughput symmetric file encryption via **AES-256-GCM** (NIST SP 800-38D, 96-bit CSPRNG nonces, 128-bit authentication tags).
   - Asymmetric Key Encapsulation Mechanism (**RSA-2048 OAEP** with SHA-256/MGF1) for secure session key transmission to designated attending physicians.
   - Non-repudiable digital signatures via **RSA-2048 PSS**.
2. **Content-Addressable Off-Chain Storage (CAS)**:
   - Stores encrypted diagnostic records off-chain under SHA-256 Content Identifiers (CIDs) with on-read bit-flip tamper detection.
   - Prevents ledger bloat and slashes smart contract gas costs by **89.8%**.
3. **Consortium Blockchain Ledger Engine**:
   - Single-node Proof-of-Authority (PoA) blockchain prototype with persistent JSON storage (`blockchain_ledger.json`).
   - Cryptographic SHA-256 sequential block chaining, dynamic time-locked consent expiration, and instant zero-reencryption permission revocation $O(1)$.
4. **PyQt5 Desktop Hospital Workstations**:
   - Clinical dual-portal workstation featuring dedicated Patient Consent Workspaces and Physician Diagnostic Review consoles.
   - Real-time multi-terminal synchronization and live blockchain ledger inspection.

---

## 2. Directory Structure

```
HealthLedger/
│
├── gui_app.py                 # Main PyQt5 Desktop Hospital Application
├── blockchain.py              # Consortium Blockchain engine with JSON persistence
├── database.py                # SQLite database & RSA-2048 keypair management
├── crypto_utils.py            # AES-256-GCM and RSA-2048 cryptographic primitives
├── storage.py                 # Off-chain Content-Addressable Storage (CAS) manager
├── test_suite.py              # 16-Test Automated Functional & Security Suite
├── benchmark_experiments.py   # Latency & throughput empirical benchmarking engine
├── seed_healthcare_data.py    # Seeds realistic clinical diagnostic records & accounts
│
├── blockchain_ledger.json     # Persistent JSON blockchain state file
├── healthcare.db              # SQLite database with registered hospital nodes & users
│
├── offchain_storage/          # Directory storing encrypted CAS payloads by CID
├── experiments/               # Empirical benchmark data, JSON logs, and charts
├── screenshots/               # Application UI figures and workstation captures
│
├── run_app.bat                # Windows double-click launcher for Desktop GUI
├── run_tests.bat              # Windows double-click runner for Test Suite
├── requirements.txt           # Project dependencies (PyQt5, cryptography, etc.)
└── README.md                  # System documentation and execution guide
```

---

## 3. Installation & Setup

### Prerequisites
- Python 3.9+ (64-bit recommended)
- Windows 10 / 11

### Step 1: Install Dependencies
Open a command prompt in this directory and execute:
```bash
pip install -r requirements.txt
```
*(Dependencies: `PyQt5`, `cryptography`, `matplotlib`, `numpy`, `pycryptodome`, `pypdf`, `reportlab`)*

---

## 4. How to Run

#### Launch the Desktop Application
```bash
python gui_app.py
```
*(or `python main.py`)*

<img width="1516" height="749" alt="figure_6_1_login" src="https://github.com/user-attachments/assets/c13be029-5256-446a-a6df-7e206a38230b" />
