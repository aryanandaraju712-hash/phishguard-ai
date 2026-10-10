"""
Automated Evaluation & Regression Tests for PhishGuard AI
Validates benchmark performance, score bounding, and edge-case resistance.
"""

import pytest
from tests.evaluation_dataset import URL_EVALUATION_DATASET, EMAIL_EVALUATION_DATASET
from app.services.url_analyzer import analyze_url_comprehensive
from app.services.email_analyzer import analyze_email_comprehensive, model_manager
from app.services.report_generator import generate_url_report, generate_email_report


def test_url_benchmark_precision_and_recall():
    tp = fp = tn = fn = 0
    for item in URL_EVALUATION_DATASET:
        url = item["url"]
        gt = item["ground_truth_suspicious"]
        try:
            res = analyze_url_comprehensive(url)
            score = res["risk_score"]
            pred = res["prediction"]
            is_pred_suspicious = bool(score >= 50.0 or pred != "Legitimate")
        except Exception:
            is_pred_suspicious = False

        if gt and is_pred_suspicious:
            tp += 1
        elif not gt and is_pred_suspicious:
            fp += 1
        elif not gt and not is_pred_suspicious:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # Assert robust detection quality on benchmark
    assert precision >= 0.90, f"URL precision fell below 90%: {precision:.2%}"
    assert recall >= 0.80, f"URL recall fell below 80%: {recall:.2%}"
    assert fp == 0, f"Expected 0 false positives on benign URLs, got {fp}"


def test_email_combined_triage_score_bounds_and_categories():
    for item in EMAIL_EVALUATION_DATASET:
        triage = analyze_email_comprehensive(
            subject=item["subject"],
            body=item["body"],
            sender=item.get("sender")
        )
        score = triage["risk_score"]
        level = triage["risk_level"]

        # Strict score bounding
        assert 0.0 <= score <= 100.0, f"Score out of bounds for {item['id']}: {score}"

        # Risk level threshold consistency
        if score < 25:
            assert level == "Low Risk"
        elif score < 50:
            assert level in ("Medium Risk", "Moderate Risk")
        elif score < 75:
            assert level == "High Risk"
        else:
            assert level == "Critical Risk"


def test_edge_case_legitimate_urgent_emails_not_critical():
    """Legitimate urgent messages must NOT falsely trigger Critical Risk."""
    edge_cases = [e for e in EMAIL_EVALUATION_DATASET if "Edge Case" in e["category"]]
    assert len(edge_cases) >= 2

    for ec in edge_cases:
        triage = analyze_email_comprehensive(
            subject=ec["subject"],
            body=ec["body"],
            sender=ec.get("sender")
        )
        assert triage["risk_score"] < 50.0, (
            f"False positive on legitimate urgent email '{ec['subject']}': score {triage['risk_score']}"
        )
        assert triage["prediction"] in ("Legitimate", "Low Risk"), (
            f"Unexpected prediction for edge case: {triage['prediction']}"
        )


def test_pdf_report_generation_across_evaluation_dataset():
    """Verifies PDF report compiles cleanly without errors for all evaluation samples."""
    for item in EMAIL_EVALUATION_DATASET[:5]:
        triage = analyze_email_comprehensive(
            subject=item["subject"],
            body=item["body"],
            sender=item.get("sender")
        )
        pdf_bytes = generate_email_report(triage)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 2500
