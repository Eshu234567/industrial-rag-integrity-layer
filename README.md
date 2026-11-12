# Beyond Metadata Filtering: An Authorization-Integrity Layer for Secure Multi-Tenant Industrial RAG Systems

**SDG 9 — Industry, Innovation and Infrastructure**  
*EL Phase-II Prototype & Reproducible Research Artifact*

---

## Overview

Shared multi-tenant Retrieval-Augmented Generation (RAG) systems in industrial environments typically rely on vector database metadata filtering to isolate confidential tenant documents. However, **metadata filtering is only as trustworthy as its labels and synchronization state**: mislabeled ingestion tags, targeted metadata poisoning, stale permissions after policy revocations, or missing policy records can cause cross-tenant confidentiality breaches.

This repository implements an **Authorization-Integrity Layer** that validates document authorization independently of retrieval metadata against an authoritative **Trusted Policy Registry** with **Candidate-Level Enforcement**, **Fail-Closed Semantics**, **Quarantine Isolation**, and **Runtime Revocation Handling**.

---

## System Architecture

1. **Ingestion & Integrity Validation Path**
   - Validates incoming industrial documents (Maintenance Manuals, SOPs, Supplier Specifications) against the **Trusted Policy Registry** before vector indexing.
   - Routes mismatched or unverifiable documents directly to the **Quarantine Store**.
2. **Query & Retrieval Gateway Path**
   - **Query API & Retriever**: Performs top-$k$ vector similarity search over the shared industrial corpus.
   - **Retrieval Gateway**: Intercepts every candidate chunk prior to LLM context assembly and queries the **Authorization Decision Engine**.
   - **Fail-Closed Enforcement**: Any candidate with a metadata-policy discrepancy, revoked permission version, corrupted HMAC signature, or unreachable policy service is **denied (fail-closed)**, logged in the **Immutable Audit Log**, and never sent to the LLM.
3. **Control Plane (Trusted Enforcement Boundary)**
   - **Trusted Policy Registry**: Maintains authoritative document ownership, allowed tenant lists, policy version numbers, and HMAC-SHA256 signatures.
   - **Revocation & Consistency Handler**: Immediately increments policy versions upon revocation without requiring expensive vector index rebuilds.

---

## Repository Structure

```text
├── app.py                      # Zero-dependency Python HTTP Server & REST API (port 8050)
├── rag_engine.py               # Core RAG Engine, Trusted Policy Registry, Fault Injection & Evaluator
├── evaluate.py                 # CLI Stage-5 Evaluation Benchmark & Standalone HTML Bundler
├── Open_Presentation_UI.html   # Single-file standalone interactive UI (works offline in any browser)
├── start_demo.bat              # One-click Windows launcher for live server + browser UI
└── static/
    ├── index.html              # Interactive 3-Tab Phase-II Demonstration Dashboard
    ├── styles.css              # Dashboard styling
    └── app.js                  # Frontend controller + built-in local fallback engine
```

---

## Quick Start

### Option 1: Instant Browser UI (Zero Setup)
Open `Open_Presentation_UI.html` directly in any modern browser (Chrome, Edge, Firefox).

### Option 2: Run the Python Backend Server + Web UI
```bash
python app.py
```
Then open `http://localhost:8050` in your browser (or double-click `start_demo.bat` on Windows).

### Option 3: Run the Stage-5 CLI Benchmark Suite
```bash
python evaluate.py
```

---

## Stage-5 Evaluation Summary

| Architecture / Baseline | Cross-Tenant Leakage Rate ↓ | Discrepancy Detection ↑ | Revocation Enforcement Delay | Authorized Recall@5 ↑ | Authorized nDCG@5 ↑ | p95 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline 1: Shared Index + Metadata Filter** | 100.0% | 0.0% | Infinite (Requires Re-index) | 1.000 | 1.000 | ~1.82 ms |
| **Baseline 2: Separate Index per Tenant** | 50.0% | 0.0% | Stale until Index Rebuild | 1.000 | 1.000 | ~2.42 ms |
| **Proposed: Authorization-Integrity Layer** | **0.0%** | **100.0%** | **0 ms (Immediate Runtime)** | **1.000** | **1.000** | **~3.17 ms** |
