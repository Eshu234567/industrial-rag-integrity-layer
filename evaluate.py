"""
Stage 5 Reproducible CLI Benchmark & Standalone HTML Bundler
For EL Phase-II Presentation:
"Beyond Metadata Filtering: An Authorization-Integrity Layer for Secure Multi-Tenant Industrial RAG Systems"
"""

import os
from rag_engine import IndustrialRAGSystem


def bundle_standalone_html() -> None:
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, "static", "index.html"), "r", encoding="utf-8") as f:
        html = f.read()
    with open(os.path.join(base, "static", "styles.css"), "r", encoding="utf-8") as f:
        css = f.read()
    with open(os.path.join(base, "static", "app.js"), "r", encoding="utf-8") as f:
        js = f.read()

    bundled = html.replace(
        '<link rel="stylesheet" href="/styles.css" />', f"<style>\n{css}\n</style>"
    ).replace('<script src="/app.js"></script>', f"<script>\n{js}\n</script>")

    out_path = os.path.join(base, "Open_Presentation_UI.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(bundled)
    print(f"[+] Created standalone single-file UI: {out_path} ({len(bundled):,} bytes)")


def run_cli_evaluation() -> None:
    system = IndustrialRAGSystem()
    report = system.run_evaluation_benchmark(iterations=5)
    summary = report["summary"]

    print("\n" + "=" * 95)
    print("  STAGE 5 EVALUATION BENCHMARK — MULTI-TENANT INDUSTRIAL RAG AUTHORIZATION INTEGRITY")
    print("=" * 95)
    header = f"{'Architecture':<42} | {'Leakage':<8} | {'Detect':<8} | {'Recall@5':<8} | {'nDCG@5':<8} | {'p95 Lat':<8}"
    print(header)
    print("-" * 95)
    for key in ["shared_filter", "separate_index", "integrity_layer"]:
        row = summary[key]
        print(
            f"{row['name']:<42} | "
            f"{str(row['leakage_rate_pct']) + '%':<8} | "
            f"{str(row['discrepancy_detection_pct']) + '%':<8} | "
            f"{row['recall_at_5']:<8.3f} | "
            f"{row['ndcg_at_5']:<8.3f} | "
            f"{str(row['p95_latency_ms']) + ' ms':<8}"
        )
    print("=" * 95)
    print("\nControlled Fault Scenarios:")
    for sc in report["scenarios"]:
        print(f"  * {sc['scenario']}")
        print(f"      - Baseline 1 (Metadata Filter): {sc['shared_filter_outcome']}")
        print(f"      - Baseline 2 (Separate Index) : {sc['separate_index_outcome']}")
        print(f"      - Proposed Integrity Layer    : {sc['integrity_layer_outcome']}")
    print()


if __name__ == "__main__":
    bundle_standalone_html()
    run_cli_evaluation()
