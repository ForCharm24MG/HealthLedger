"""
seed_healthcare_data.py
Populates HealthLedger with realistic, authentic clinical healthcare data for M.Sc. IT Research Viva Defense.
Seeds:
- 3 Verified Patients (Alice Smith, Manish Ghag [Roll No. 603], Aman Gupta)
- 3 Verified Physicians (Dr. Bob Sharma - Cardiology, Dr. Clara Rao - Neurology, Dr. Rajesh Sharma - Oncology)
- Realistic encrypted clinical diagnostic reports in off-chain CAS storage
- Anchored blockchain transactions with RSA-PSS digital signatures and active time-locked consents
"""

import os
import sys
import time
import json
import io

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

import crypto_utils
import database
import storage
from blockchain import HealthcareBlockchain, LEDGER_FILE

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
        elif any(line_clean.startswith(h) for h in ['FINDINGS:', 'IMPRESSION:', 'TEST RESULTS:', 'CLINICAL INTERPRETATION:', 'OPERATIVE SUMMARY:', 'DISCHARGE ADVICE:']):
            story.append(Paragraph(f"<b>{line_clean}</b>", section_style))
        else:
            story.append(Paragraph(line_clean, body_style))
    doc.build(story)
    return buf.getvalue()

def seed_complete_healthcare_system():
    print("[*] Initializing Healthcare Data Sharing System seeding...")
    
    # 1. Initialize databases and directories
    storage.clear_storage()
    conn = database.get_connection()
    cur = conn.cursor()
    
    # Clean previous tables to avoid stale test users like '123532333' or 'df'
    cur.execute("DELETE FROM records")
    cur.execute("DELETE FROM users")
    conn.commit()
    
    # 2. Seed Realistic Users
    users_to_seed = [
        # (username, password, full_name, role, department, hospital)
        ("alice_smith", "Password@123", "Alice Smith", "patient", "", "Metro General Hospital"),
        ("manish_ghag", "Password@123", "Manish Ghag (Roll 603)", "patient", "", "City General Health Center"),
        ("aman_gupta", "Password@123", "Aman Gupta", "patient", "", "Metro General Hospital"),
        ("dr_bob", "Password@123", "Dr. Bob Sharma, MD", "doctor", "Interventional Cardiology", "Metro Heart Center"),
        ("dr_clara", "Password@123", "Dr. Clara Rao, MD, DM", "doctor", "Consultant Neurology", "Apex Neuro Specialty Clinic"),
        ("dr_rajesh", "Password@123", "Dr. Rajesh Sharma, MD", "doctor", "Surgical Oncology", "City Consortium Cancer Center")
    ]
    
    user_keys = {}
    
    for u, p, fn, r, dep, hosp in users_to_seed:
        priv, pub = crypto_utils.generate_rsa_keypair()
        priv_pem = crypto_utils.export_rsa_private_key(priv)
        pub_pem = crypto_utils.export_rsa_public_key(pub)
        salt_hex, hash_hex = crypto_utils.hash_password(p)
        
        cur.execute("""
            INSERT INTO users 
            (username, full_name, role, department, hospital, password_salt, password_hash, rsa_private_key_pem, rsa_public_key_pem, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (u, fn, r, dep, hosp, salt_hex, hash_hex, priv_pem, pub_pem, time.time()))
        
        user_keys[u] = {
            "priv": priv,
            "pub": pub,
            "priv_pem": priv_pem,
            "pub_pem": pub_pem,
            "full_name": fn
        }
        print(f"  [+] Registered {r.capitalize()}: {fn} (@{u})")
        
    conn.commit()
    conn.close()
    
    # 3. Create Fresh Persistent Blockchain Ledger
    ledger_path = LEDGER_FILE
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
        
    blockchain = HealthcareBlockchain(ledger_file=ledger_path)
    print(f"  [+] Genesis Block #0 Initialized: {blockchain.chain[0].hash[:16]}...")
    
    # 4. Realistic Medical Diagnostic Reports Payloads
    clinical_records = [
        {
            "record_id": "REC-CAR-2026-001",
            "patient_u": "alice_smith",
            "title": "12-Lead Electrocardiogram & 2D Doppler Echocardiography",
            "category": "Cardiology",
            "file_name": "Alice_Smith_Cardiac_ECG_Echo_Report.pdf",
            "diagnosis": "Normal sinus rhythm (72 bpm). Mild mitral valve leaflet thickening without significant regurgitation. Left ventricular ejection fraction (LVEF): 62%. No regional wall motion abnormality detected.",
            "file_content": (
                "METRO HEART CENTER - CLINICAL DIAGNOSTIC DIVISION\n"
                "Patient: Alice Smith | Age: 34 | Gender: Female | MRN: MED-88219\n"
                "Referring Physician: Dr. Bob Sharma, MD (Cardiology)\n"
                "Procedure: 12-Lead Electrocardiogram (ECG) and Transthoracic 2D Doppler Echocardiography\n"
                "------------------------------------------------------------------------------------\n"
                "FINDINGS:\n"
                "1. Cardiac rhythm: Regular sinus rhythm with physiological heart rate variability.\n"
                "2. PR Interval: 156 ms (Normal), QRS Duration: 88 ms (Normal), QTc: 418 ms.\n"
                "3. Doppler interrogation shows normal peak aortic velocity (1.3 m/s).\n"
                "4. LVEF calculated at 62% by Simpson's biplane method.\n"
                "IMPRESSION:\n"
                "Structurally preserved myocardial mechanics. Hemodynamically stable. Routine annual follow-up."
            )
        },
        {
            "record_id": "REC-NEU-2026-002",
            "patient_u": "alice_smith",
            "title": "Brain Magnetic Resonance Imaging (MRI) Contrast Protocol",
            "category": "Neurology",
            "file_name": "Alice_Smith_Brain_MRI_Neuro_Report.pdf",
            "diagnosis": "Axial T1/T2/FLAIR sequences demonstrate normal cerebral parenchyma. No acute intracranial hemorrhage, territorial infarction, or mass effect. Craniovertebral junction is intact.",
            "file_content": (
                "APEX NEURO SPECIALTY INSTITUTE - DIAGNOSTIC NEURORADIOLOGY\n"
                "Patient: Alice Smith | Age: 34 | Gender: Female | MRN: MED-88219\n"
                "Neurologist: Dr. Clara Rao, MD, DM\n"
                "Procedure: High-Resolution 3.0T Brain MRI with IV Gadolinium Contrast\n"
                "------------------------------------------------------------------------------------\n"
                "FINDINGS:\n"
                "1. Grey-white matter differentiation is preserved symmetrically throughout both hemispheres.\n"
                "2. Ventricular chambers, basal cisterns, and cerebral sulci show normal morphology.\n"
                "3. Diffusion weighted imaging (DWI) shows no restricted water diffusion.\n"
                "4. Post-contrast images demonstrate physiological enhancement without abnormal leptomeningeal focus.\n"
                "IMPRESSION:\n"
                "Unremarkable 3.0T Cranial MRI study. Cephalea workup negative for organic intracranial lesions."
            )
        },
        {
            "record_id": "REC-LAB-2026-003",
            "patient_u": "manish_ghag",
            "title": "Comprehensive Preventive Biochemistry & Metabolic Panel",
            "category": "Pathology",
            "file_name": "Manish_Ghag_Biochemistry_HbA1c_Panel.pdf",
            "diagnosis": "Fasting Plasma Glucose: 91 mg/dL, Glycated Hemoglobin (HbA1c): 5.4% (Non-Diabetic). Lipid profile and renal indices (Serum Creatinine 0.9 mg/dL) within optimal reference limits.",
            "file_content": (
                "CONSORTIUM CLINICAL LABORATORY - CLINICAL BIOCHEMISTRY\n"
                "Patient: Manish Ghag | Age: 23 | Gender: Male | Roll No: 603 | MRN: MED-2026-603\n"
                "Center: City Healthcare Diagnostic Center, Mumbai\n"
                "Panel: Comprehensive Preventive Health & Glycemic Biomarker Screen\n"
                "------------------------------------------------------------------------------------\n"
                "TEST RESULTS:\n"
                "- Fasting Blood Sugar: 91 mg/dL (Reference: 70 - 99 mg/dL) [NORMAL]\n"
                "- Glycated Hemoglobin (HbA1c): 5.4% (Reference: < 5.7%) [OPTIMAL]\n"
                "- Total Cholesterol: 165 mg/dL (Reference: < 200 mg/dL) [OPTIMAL]\n"
                "- HDL ('Good') Cholesterol: 52 mg/dL (Reference: > 40 mg/dL)\n"
                "- Triglycerides: 110 mg/dL (Reference: < 150 mg/dL)\n"
                "- Serum Creatinine: 0.92 mg/dL | eGFR: > 90 mL/min/1.73m2\n"
                "CLINICAL INTERPRETATION:\n"
                "Excellent metabolic, cardiovascular, and renal profile. All biomarker parameters conform to optimal clinical reference standards."
            )
        },
        {
            "record_id": "REC-ORT-2026-004",
            "patient_u": "aman_gupta",
            "title": "Post-Operative Arthroscopic ACL Reconstruction Discharge Summary",
            "category": "Surgery",
            "file_name": "Aman_Gupta_Orthopedic_Discharge_Summary.pdf",
            "diagnosis": "Successful left knee arthroscopic ACL reconstruction using autologous hamstrings graft. Wound clean, neurovascular status intact. Initiated Phase 1 progressive physical therapy.",
            "file_content": (
                "METRO GENERAL HOSPITAL - DEPARTMENT OF ORTHOPEDIC SURGERY\n"
                "Patient: Aman Gupta | Age: 42 | Gender: Male | MRN: MED-71405\n"
                "Department: Orthopedics & Sports Medicine | Hospital: Metro General\n"
                "Procedure: Arthroscopic Anterior Cruciate Ligament (ACL) Reconstruction (Left Knee)\n"
                "------------------------------------------------------------------------------------\n"
                "OPERATIVE SUMMARY:\n"
                "Patient underwent uneventful left knee arthroscopic reconstruction with quadruple semitendinosus graft.\n"
                "Femoral and tibial tunnel fixation achieved with biodegradable interference screws.\n"
                "Negative anterior drawer and Lachman tests confirmed intra-operatively.\n"
                "DISCHARGE ADVICE:\n"
                "Rigid hinged knee brace locked at 0-90 degrees for ambulation. Cryotherapy q.i.d. Physical therapy 3x/week."
            )
        }
    ]
    
    # 5. Encrypt and store each record, anchor on blockchain, record in SQLite
    for rec in clinical_records:
        pat_u = rec["patient_u"]
        pat_keys = user_keys[pat_u]
        
        # A. Client-side symmetric encryption (AES-256-GCM)
        aes_key = crypto_utils.generate_aes_key()
        raw_bytes = rec["file_content"].encode('utf-8')
        ciphertext_hex, nonce_hex = crypto_utils.encrypt_bytes(raw_bytes, aes_key)
        data_hash = crypto_utils.compute_bytes_hash(raw_bytes)
        
        # B. Encapsulate AES key for the patient's own RSA public key
        enc_aes_pat = crypto_utils.encrypt_key_for_recipient(aes_key, pat_keys["pub"])
        
        # C. Off-chain Content-Addressed Storage (CAS) write
        storage_meta = {
            "record_id": rec["record_id"],
            "patient_username": pat_u,
            "title": rec["title"],
            "category": rec["category"],
            "file_name": rec["file_name"],
            "file_size": len(raw_bytes),
            "data_hash": data_hash
        }
        content_hash = storage.save_to_storage(ciphertext_hex, nonce_hex, metadata=storage_meta)
        
        # D. Patient digitally signs the anchor transaction (RSA-PSS)
        sign_payload = f"{rec['record_id']}:{content_hash}:{data_hash}".encode('utf-8')
        pat_sig = crypto_utils.sign_data(sign_payload, pat_keys["priv"])
        
        # E. Add anchor to blockchain transaction pool
        blockchain.add_record_anchor(
            patient_id=pat_u,
            record_id=rec["record_id"],
            content_hash=content_hash,
            data_hash=data_hash,
            record_type=rec["category"],
            patient_signature=pat_sig
        )
        
        # Mine block for each record anchor
        new_block = blockchain.mine_block()
        block_idx = new_block.index
        
        # F. Insert record metadata into SQLite
        database.insert_record(
            record_id=rec["record_id"],
            patient_username=pat_u,
            title=rec["title"],
            diagnosis=rec["diagnosis"],
            category=rec["category"],
            file_name=rec["file_name"],
            file_size=len(raw_bytes),
            content_hash=content_hash,
            data_hash=data_hash,
            block_index=block_idx,
            encrypted_aes_key_patient=enc_aes_pat
        )
        rec["aes_key"] = aes_key
        rec["content_hash"] = content_hash
        print(f"  [+] Anchored {rec['record_id']} on Block #{block_idx} (CID: {content_hash[:16]}...)")
        
    # 6. Seed Active Time-Locked Consents with Digital Signatures
    # Consent 1: Alice Smith grants 24-hour access to Dr. Bob Sharma for Record 1 (Cardiology)
    alice_rec1 = clinical_records[0]
    enc_key_for_bob = crypto_utils.encrypt_key_for_recipient(alice_rec1["aes_key"], user_keys["dr_bob"]["pub"])
    consent_payload1 = f"alice_smith:{alice_rec1['record_id']}:dr_bob:86400".encode('utf-8')
    alice_sig1 = crypto_utils.sign_data(consent_payload1, user_keys["alice_smith"]["priv"])
    
    blockchain.grant_consent(
        patient_id="alice_smith",
        record_id=alice_rec1["record_id"],
        doctor_id="dr_bob",
        duration_seconds=86400.0, # 24 hours
        encrypted_key_for_doctor=enc_key_for_bob,
        patient_signature=alice_sig1
    )
    b_consent1 = blockchain.mine_block()
    print(f"  [+] Mined Consent Block #{b_consent1.index}: Alice Smith -> Dr. Bob Sharma (24h time-lock)")
    
    # Simulate Dr. Bob accessing and decrypting Record 1 (Authorized audit trail)
    blockchain.log_record_access(patient_id="alice_smith", record_id=alice_rec1["record_id"], doctor_id="dr_bob")
    b_audit1 = blockchain.mine_block()
    print(f"  [+] Mined Access Audit Block #{b_audit1.index}: Dr. Bob Sharma verified & decrypted ECG file")
    
    # Consent 2: Manish Ghag grants 48-hour access to Dr. Clara Rao for Record 3 (Biochemistry)
    manish_rec3 = clinical_records[2]
    enc_key_for_clara = crypto_utils.encrypt_key_for_recipient(manish_rec3["aes_key"], user_keys["dr_clara"]["pub"])
    consent_payload2 = f"manish_ghag:{manish_rec3['record_id']}:dr_clara:172800".encode('utf-8')
    manish_sig2 = crypto_utils.sign_data(consent_payload2, user_keys["manish_ghag"]["priv"])
    
    blockchain.grant_consent(
        patient_id="manish_ghag",
        record_id=manish_rec3["record_id"],
        doctor_id="dr_clara",
        duration_seconds=172800.0, # 48 hours
        encrypted_key_for_doctor=enc_key_for_clara,
        patient_signature=manish_sig2
    )
    b_consent2 = blockchain.mine_block()
    print(f"  [+] Mined Consent Block #{b_consent2.index}: Manish Ghag (Roll 603) -> Dr. Clara Rao (48h time-lock)")
    
    blockchain.save_to_disk()
    print("[*] Healthcare Data Seeding COMPLETE: 6 Users, 4 Encrypted Records, 7 Blocks Mined!")

if __name__ == "__main__":
    seed_complete_healthcare_system()
