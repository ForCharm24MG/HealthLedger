"""
benchmark_experiments.py
Empirical Benchmarking & Performance Evaluation Suite for HealthLedger.
Measures cryptographic execution latency, throughput, storage amplification,
and CAS content addressing overhead across 6 standardized HL7 FHIR clinical payload tiers.
Runs on: AMD Ryzen 5 5600H with Radeon Graphics (6 Cores / 12 Logical Processors), 8 GB RAM, Python 3.9.13.
Performs 10 repeated iterations per tier, calculates statistical mean and standard deviation,
distinguishes raw OpenSSL AES-NI hardware-accelerated cipher execution from application wrapper serialization,
saves raw measurements to JSON, and produces reproducible publication-grade charts.
"""

import os
import sys
import time
import json
import statistics
import tempfile
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_utils
import storage
import database
import blockchain

EXPERIMENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiments")
os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

# 6 Clinical Payload Tiers for Enterprise Healthcare Benchmark
DATASET_TIERS = [
    ("Tier 1 (100 KB)",  100 * 1024,        "Lab Biochemistry & Hematology Panels"),
    ("Tier 2 (500 KB)",  500 * 1024,        "Complete Outpatient Consultation EHR"),
    ("Tier 3 (1.0 MB)",  1 * 1024 * 1024,   "Genomic Exome Sequencing Records"),
    ("Tier 4 (5.0 MB)",  5 * 1024 * 1024,   "High-Resolution Pediatric Chest X-Ray"),
    ("Tier 5 (10.0 MB)", 10 * 1024 * 1024,  "Multislice Head & Neck CT Scans"),
    ("Tier 6 (25.0 MB)", 25 * 1024 * 1024,  "High-Resolution Diagnostic Lumbar Spine MRI")
]

NUM_RUNS = 10

def generate_synthetic_payload(size_bytes: int) -> bytes:
    """Generates synthetic pseudo-clinical structured bytes to simulate medical payload."""
    header = b"%PDF-1.4 [SYNTHETIC HL7 FHIR CLINICAL DATASET - HEALTHLEDGER EVALUATION]\n"
    chunk = b"RECORD_TYPE: DIAGNOSTIC_IMAGING_OR_CLINICAL_NOTE; HL7_VERSION: 5.0; INTEGRITY_MODE: AES256_GCM;\n" * 128
    repeats = (size_bytes - len(header)) // len(chunk)
    remainder = size_bytes - len(header) - (repeats * len(chunk))
    return header + (chunk * repeats) + os.urandom(remainder)

def run_benchmarks():
    print("=" * 105)
    print("  HEALTHLEDGER: REPRODUCIBLE EMPIRICAL BENCHMARK SUITE")
    print("  Host CPU: AMD Ryzen 5 5600H with Radeon Graphics (6 Cores / 12 Logical Processors)")
    print(f"  Iterations per tier: {NUM_RUNS} (with 1 initial discarded warm-up run)")
    print("=" * 105)

    summary_records = []
    raw_measurements = {}

    for label, size_bytes, desc in DATASET_TIERS:
        size_mb = size_bytes / (1024 * 1024)
        print(f"\n[Running Benchmark] {label} ({size_mb:.2f} MB) - {desc}")
        
        # Pre-generate synthetic clinical payload
        payload = generate_synthetic_payload(size_bytes)
        aes_key = crypto_utils.generate_aes_key()
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)

        # Warm-up run (to prime CPU cache / branch predictor)
        w_c, w_n = crypto_utils.encrypt_bytes(payload, aes_key)
        _ = crypto_utils.decrypt_bytes(w_c, w_n, aes_key)
        _ = aesgcm.decrypt(nonce, aesgcm.encrypt(nonce, payload, None), None)

        raw_enc_latencies = []
        raw_dec_latencies = []
        wrap_enc_latencies = []
        wrap_dec_latencies = []
        cas_write_latencies = []
        ciphertext_sizes = []

        for run_idx in range(NUM_RUNS):
            # A. Pure Raw AES-NI C-Extension Encryption & Decryption (OpenSSL core)
            t0 = time.perf_counter()
            c_raw = aesgcm.encrypt(nonce, payload, None)
            t_raw_enc = (time.perf_counter() - t0) * 1000
            raw_enc_latencies.append(t_raw_enc)

            t0 = time.perf_counter()
            _ = aesgcm.decrypt(nonce, c_raw, None)
            t_raw_dec = (time.perf_counter() - t0) * 1000
            raw_dec_latencies.append(t_raw_dec)

            # B. Application Wrapper (includes hex-encoding and string memory allocation)
            t0 = time.perf_counter()
            c_hex, n_hex = crypto_utils.encrypt_bytes(payload, aes_key)
            t_wrap_enc = (time.perf_counter() - t0) * 1000
            wrap_enc_latencies.append(t_wrap_enc)

            c_size_bytes = len(c_hex) // 2
            ciphertext_sizes.append(c_size_bytes)

            t0 = time.perf_counter()
            dec_bytes = crypto_utils.decrypt_bytes(c_hex, n_hex, aes_key)
            t_wrap_dec = (time.perf_counter() - t0) * 1000
            wrap_dec_latencies.append(t_wrap_dec)

            assert dec_bytes == payload, "Decryption integrity verification failed!"

            # C. Off-Chain CAS write
            t0 = time.perf_counter()
            cid = storage.save_to_storage(c_hex, n_hex, {"size": size_bytes})
            t_cas = (time.perf_counter() - t0) * 1000
            cas_write_latencies.append(t_cas)

        # Statistical calculations: Raw OpenSSL AES-NI C-Extension
        mean_raw_enc = statistics.mean(raw_enc_latencies)
        mean_raw_dec = statistics.mean(raw_dec_latencies)
        raw_enc_tp = size_mb / (mean_raw_enc / 1000.0)
        raw_dec_tp = size_mb / (mean_raw_dec / 1000.0)

        # Statistical calculations: Application Wrapper
        mean_wrap_enc = statistics.mean(wrap_enc_latencies)
        stdev_wrap_enc = statistics.stdev(wrap_enc_latencies) if len(wrap_enc_latencies) > 1 else 0.0
        mean_wrap_dec = statistics.mean(wrap_dec_latencies)
        stdev_wrap_dec = statistics.stdev(wrap_dec_latencies) if len(wrap_dec_latencies) > 1 else 0.0
        wrap_enc_tp = size_mb / (mean_wrap_enc / 1000.0)
        wrap_dec_tp = size_mb / (mean_wrap_dec / 1000.0)

        mean_cas_write = statistics.mean(cas_write_latencies)
        mean_c_size = statistics.mean(ciphertext_sizes)
        storage_amp_ratio = (mean_c_size + 12) / size_bytes

        print(f"  [Raw OpenSSL AES-NI]  Enc: {mean_raw_enc:.2f} ms ({raw_enc_tp:,.1f} MB/s) | Dec: {mean_raw_dec:.2f} ms ({raw_dec_tp:,.1f} MB/s)")
        print(f"  [App Wrapper (Hex)]   Enc: {mean_wrap_enc:.2f} ms +/- {stdev_wrap_enc:.2f} ms ({wrap_enc_tp:,.1f} MB/s) | Dec: {mean_wrap_dec:.2f} ms +/- {stdev_wrap_dec:.2f} ms ({wrap_dec_tp:,.1f} MB/s)")
        print(f"  [CAS Storage Write]   Latency: {mean_cas_write:.2f} ms | Storage Amp Ratio: {storage_amp_ratio:.4f}")

        tier_summary = {
            "tier_label": label,
            "size_bytes": size_bytes,
            "size_mb": round(size_mb, 4),
            "description": desc,
            # Raw OpenSSL Hardware C-Cipher Performance
            "raw_cipher_enc_latency_mean_ms": round(mean_raw_enc, 3),
            "raw_cipher_enc_throughput_mb_s": round(raw_enc_tp, 1),
            "raw_cipher_dec_latency_mean_ms": round(mean_raw_dec, 3),
            "raw_cipher_dec_throughput_mb_s": round(raw_dec_tp, 1),
            # Application Wrapper Performance (including hex serialization)
            "wrapper_enc_latency_mean_ms": round(mean_wrap_enc, 3),
            "wrapper_enc_latency_stdev_ms": round(stdev_wrap_enc, 3),
            "wrapper_enc_throughput_mb_s": round(wrap_enc_tp, 1),
            "wrapper_dec_latency_mean_ms": round(mean_wrap_dec, 3),
            "wrapper_dec_latency_stdev_ms": round(stdev_wrap_dec, 3),
            "wrapper_dec_throughput_mb_s": round(wrap_dec_tp, 1),
            # CAS Storage Layer
            "cas_write_latency_mean_ms": round(mean_cas_write, 3),
            "storage_amplification_ratio": round(storage_amp_ratio, 4)
        }
        summary_records.append(tier_summary)
        raw_measurements[label] = {
            "raw_enc_latencies_ms": raw_enc_latencies,
            "raw_dec_latencies_ms": raw_dec_latencies,
            "wrapper_enc_latencies_ms": wrap_enc_latencies,
            "wrapper_dec_latencies_ms": wrap_dec_latencies,
            "cas_write_latencies_ms": cas_write_latencies
        }

    # -------------------------------------------------------------
    # Asymmetric Key Encapsulation & Digital Signature Benchmarks
    # -------------------------------------------------------------
    print("\n[Running Benchmark] Asymmetric Cryptography & Digital Signatures (RSA-2048, 20 runs)")
    priv, pub = crypto_utils.generate_rsa_keypair()
    aes_k = crypto_utils.generate_aes_key()
    oaep_enc_times, oaep_dec_times, pss_sign_times, pss_verify_times = [], [], [], []

    for _ in range(20):
        # OAEP Encapsulation
        t0 = time.perf_counter()
        wrapped = crypto_utils.encrypt_key_for_recipient(aes_k, pub)
        oaep_enc_times.append((time.perf_counter() - t0) * 1000)

        # OAEP Decapsulation
        t0 = time.perf_counter()
        _ = crypto_utils.decrypt_key_with_private_key(wrapped, priv)
        oaep_dec_times.append((time.perf_counter() - t0) * 1000)

        # PSS Sign
        tx_data = b"GRANT:REC-2026-001:DOC_SHARMA:86400"
        t0 = time.perf_counter()
        sig = crypto_utils.sign_data(tx_data, priv)
        pss_sign_times.append((time.perf_counter() - t0) * 1000)

        # PSS Verify
        t0 = time.perf_counter()
        _ = crypto_utils.verify_signature(tx_data, sig, pub)
        pss_verify_times.append((time.perf_counter() - t0) * 1000)

    asymm_summary = {
        "rsa_oaep_encapsulation_ms": round(statistics.mean(oaep_enc_times), 3),
        "rsa_oaep_decapsulation_ms": round(statistics.mean(oaep_dec_times), 3),
        "rsa_pss_sign_ms": round(statistics.mean(pss_sign_times), 3),
        "rsa_pss_verify_ms": round(statistics.mean(pss_verify_times), 3)
    }
    print(f"  -> RSA-2048 OAEP Encapsulation: {asymm_summary['rsa_oaep_encapsulation_ms']} ms")
    print(f"  -> RSA-2048 OAEP Decapsulation: {asymm_summary['rsa_oaep_decapsulation_ms']} ms")
    print(f"  -> RSA-PSS Digital Sign:        {asymm_summary['rsa_pss_sign_ms']} ms")
    print(f"  -> RSA-PSS Signature Verify:    {asymm_summary['rsa_pss_verify_ms']} ms")

    # Save full JSON output
    output_data = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "host_processor": "AMD Ryzen 5 5600H with Radeon Graphics (6 Cores / 12 Logical Processors)",
            "memory": "8.0 GB DDR4 Memory",
            "operating_system": "Microsoft Windows 11 Enterprise (64-bit)",
            "python_version": sys.version,
            "cipher_algorithm": "AES-256-GCM (NIST SP 800-38D)",
            "asymmetric_algorithm": "RSA-2048 OAEP (SHA-256) & RSA-PSS Signatures",
            "iterations_per_tier": NUM_RUNS
        },
        "dataset_tiers": summary_records,
        "asymmetric_benchmarks": asymm_summary,
        "raw_measurements": raw_measurements
    }

    json_path = os.path.join(EXPERIMENTS_DIR, "benchmark_results_reproducible.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"\n[Saved JSON] Benchmark outputs written to: {json_path}")

    # Generate Publication Plots
    generate_charts(summary_records)

    return output_data

def generate_charts(summary_records):
    """Generates authentic, high-resolution scientific plots from actual measured values."""
    sizes_mb = [r["size_mb"] for r in summary_records]
    wrap_enc_means = [r["wrapper_enc_latency_mean_ms"] for r in summary_records]
    wrap_enc_errs = [r["wrapper_enc_latency_stdev_ms"] for r in summary_records]
    wrap_dec_means = [r["wrapper_dec_latency_mean_ms"] for r in summary_records]
    wrap_dec_errs = [r["wrapper_dec_latency_stdev_ms"] for r in summary_records]
    
    raw_enc_means = [r["raw_cipher_enc_latency_mean_ms"] for r in summary_records]
    raw_dec_means = [r["raw_cipher_dec_latency_mean_ms"] for r in summary_records]

    wrap_enc_tps = [r["wrapper_enc_throughput_mb_s"] for r in summary_records]
    wrap_dec_tps = [r["wrapper_dec_throughput_mb_s"] for r in summary_records]

    # --- Plot 1: Latency vs Size ---
    plt.figure(figsize=(9, 5.5), dpi=300)
    plt.errorbar(sizes_mb, wrap_enc_means, yerr=wrap_enc_errs, fmt='-o', color='#1E56A0', lw=2, capsize=4, label='App Wrapper Encryption (Hex-Encoded)')
    plt.errorbar(sizes_mb, wrap_dec_means, yerr=wrap_dec_errs, fmt='-s', color='#0D9488', lw=2, capsize=4, label='App Wrapper Decryption (Hex-Encoded)')
    plt.plot(sizes_mb, raw_enc_means, '--^', color='#F59E0B', lw=1.5, label='Raw OpenSSL AES-NI C-Cipher (Core)')
    
    plt.title('Cryptographic Execution Latency vs. Clinical Payload Size\n(AMD Ryzen 5 5600H @ 3.30 GHz, 10 Runs per Tier, Mean +/- Stdev)', fontsize=12, fontweight='bold', pad=12)
    plt.xlabel('EHR Clinical Record Size (MB)', fontsize=11, fontweight='bold')
    plt.ylabel('Execution Latency (milliseconds)', fontsize=11, fontweight='bold')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend(fontsize=9.5, loc='upper left')
    plt.tight_layout()

    plot1_path = os.path.join(EXPERIMENTS_DIR, "benchmark_latency_vs_size_measured.png")
    plt.savefig(plot1_path)
    plt.close()
    print(f"[Saved Plot] Latency chart saved to: {plot1_path}")

    # --- Plot 2: Throughput vs Size ---
    plt.figure(figsize=(9, 5.5), dpi=300)
    labels = [r["tier_label"].split(" ")[1] for r in summary_records]
    x = range(len(labels))
    width = 0.35

    plt.bar([p - width/2 for p in x], wrap_enc_tps, width=width, color='#1E56A0', label='App Encryption Throughput (MB/s)')
    plt.bar([p + width/2 for p in x], wrap_dec_tps, width=width, color='#0D9488', label='App Decryption Throughput (MB/s)')

    plt.title('Application Cryptographic Throughput across Standardized Payload Tiers\n(Measured on AMD Ryzen 5 5600H Hardware)', fontsize=12, fontweight='bold', pad=12)
    plt.xlabel('Payload Tier', fontsize=11, fontweight='bold')
    plt.ylabel('Throughput (MB/s)', fontsize=11, fontweight='bold')
    plt.xticks(x, labels, fontsize=10)
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.legend(fontsize=10, loc='lower right')
    plt.tight_layout()

    plot2_path = os.path.join(EXPERIMENTS_DIR, "benchmark_throughput_measured.png")
    plt.savefig(plot2_path)
    plt.close()
    print(f"[Saved Plot] Throughput chart saved to: {plot2_path}")

if __name__ == '__main__':
    run_benchmarks()
