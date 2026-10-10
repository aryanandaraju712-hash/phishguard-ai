"""
PhishGuard AI — Benchmark Evaluation Runner
Executes comprehensive evaluation of:
1. Static URL Phishing Detection
2. Pretrained DistilBERT Model Spam Classification
3. Explainable Email Pattern Extraction
4. Combined Multi-Layered Triage Engine
5. PDF Report Consistency
"""

import sys
from pathlib import Path
from typing import Dict, Any, List

# Ensure backend root is on sys.path
backend_root = Path(__file__).resolve().parent.parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from tests.evaluation_dataset import URL_EVALUATION_DATASET, EMAIL_EVALUATION_DATASET
from app.services.url_analyzer import analyze_url_comprehensive
from app.services.email_analyzer import analyze_email_comprehensive, model_manager
from app.services.email_pattern_analyzer import analyze_email_patterns
from app.services.report_generator import generate_url_report, generate_email_report


def calculate_binary_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "total": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1
    }


def evaluate_url_detection() -> Dict[str, Any]:
    print("\n=======================================================")
    print("1. EVALUATING URL PHISHING DETECTION (STATIC HEURISTICS)")
    print("=======================================================")
    tp = fp = tn = fn = 0
    results = []

    for item in URL_EVALUATION_DATASET:
        url = item["url"]
        gt = item["ground_truth_suspicious"]
        category = item["category"]

        try:
            res = analyze_url_comprehensive(url)
            score = res["risk_score"]
            pred = res["prediction"]
            # Predicted suspicious if risk score >= 50 or prediction is not Legitimate
            is_pred_suspicious = bool(score >= 50.0 or pred != "Legitimate")
        except Exception as e:
            # Malformed URL exception handling
            score = 0.0
            pred = "Error/Malformed"
            is_pred_suspicious = False

        if gt and is_pred_suspicious:
            tp += 1
            outcome = "TP"
        elif not gt and is_pred_suspicious:
            fp += 1
            outcome = "FP"
        elif not gt and not is_pred_suspicious:
            tn += 1
            outcome = "TN"
        else:
            fn += 1
            outcome = "FN"

        results.append({
            "url": url[:60],
            "category": category,
            "ground_truth": gt,
            "pred_suspicious": is_pred_suspicious,
            "score": score,
            "prediction": pred,
            "outcome": outcome
        })
        print(f"[{outcome:2}] Score: {score:4.1f} | Category: {category:30} | URL: {url[:45]}")

    metrics = calculate_binary_metrics(tp, fp, tn, fn)
    print("\n--- URL Detection Performance Metrics ---")
    print(f"Total Evaluated: {metrics['total']}")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']:.1%})")
    print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']:.1%})")
    print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']:.1%})")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    return {"metrics": metrics, "details": results}


def evaluate_email_spam_model() -> Dict[str, Any]:
    print("\n=======================================================")
    print("2. EVALUATING PRETRAINED MODEL (SPAM VS HAM)")
    print("=======================================================")
    tp = fp = tn = fn = 0
    results = []

    for item in EMAIL_EVALUATION_DATASET:
        gt_spam = item["ground_truth_spam"]
        subject = item["subject"]
        body = item["body"]
        category = item["category"]

        # Run model classifier directly
        combined_text = f"Subject: {subject}\n\n{body}"
        clf_res = model_manager.classify_email(combined_text)
        pred_label = clf_res["model_label"]
        conf = clf_res["classification_score"]
        device = clf_res["inference_device"]
        is_pred_spam = ("LABEL_1" in pred_label or "SPAM" in pred_label.upper())

        if gt_spam and is_pred_spam:
            tp += 1
            outcome = "TP"
        elif not gt_spam and is_pred_spam:
            fp += 1
            outcome = "FP"
        elif not gt_spam and not is_pred_spam:
            tn += 1
            outcome = "TN"
        else:
            fn += 1
            outcome = "FN"

        results.append({
            "id": item["id"],
            "category": category,
            "ground_truth_spam": gt_spam,
            "pred_label": pred_label,
            "confidence": conf,
            "outcome": outcome
        })
        print(f"[{outcome:2}] Label: {pred_label:7} ({conf:.1%}) | Device: {device:12} | Category: {category:30}")

    metrics = calculate_binary_metrics(tp, fp, tn, fn)
    print("\n--- Pretrained Model Spam Classification Metrics ---")
    print(f"Total Evaluated: {metrics['total']}")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']:.1%})")
    print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']:.1%})")
    print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']:.1%})")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    return {"metrics": metrics, "details": results}


def evaluate_email_pattern_analyzer() -> Dict[str, Any]:
    print("\n=======================================================")
    print("3. EVALUATING EXPLAINABLE EMAIL PATTERN ANALYZER")
    print("=======================================================")
    results = []

    for item in EMAIL_EVALUATION_DATASET:
        subject = item["subject"]
        body = item["body"]
        sender = item.get("sender", "")
        category = item["category"]

        indicators = analyze_email_patterns(subject=subject, body=body, sender=sender)
        categories_flagged = [ind["category"] for ind in indicators]

        results.append({
            "id": item["id"],
            "category": category,
            "indicators_count": len(indicators),
            "flagged": categories_flagged
        })
        print(f"ID: {item['id']:13} | Flagged ({len(indicators)}): {', '.join(categories_flagged[:2]) or 'None'}")

    return {"details": results}


def evaluate_combined_triage() -> Dict[str, Any]:
    print("\n=======================================================")
    print("4. EVALUATING COMBINED MULTI-LAYERED TRIAGE ENGINE")
    print("=======================================================")
    tp = fp = tn = fn = 0
    results = []

    for item in EMAIL_EVALUATION_DATASET:
        gt_threat = item["ground_truth_suspicious"]
        subject = item["subject"]
        body = item["body"]
        sender = item.get("sender")
        category = item["category"]

        triage = analyze_email_comprehensive(subject=subject, body=body, sender=sender)
        score = triage["risk_score"]
        level = triage["risk_level"]
        pred = triage["prediction"]

        # Bound checks
        assert 0.0 <= score <= 100.0, f"Score out of bounds: {score}"

        # Risk level alignment check
        if score < 25:
            assert level == "Low Risk", f"Level mismatch for {score}: {level}"
        elif score < 50:
            assert level in ("Medium Risk", "Moderate Risk"), f"Level mismatch for {score}: {level}"
        elif score < 75:
            assert level == "High Risk", f"Level mismatch for {score}: {level}"
        else:
            assert level == "Critical Risk", f"Level mismatch for {score}: {level}"

        is_pred_threat = bool(score >= 50.0 or pred in ("Potential Phishing", "Spam", "Suspicious"))

        if gt_threat and is_pred_threat:
            tp += 1
            outcome = "TP"
        elif not gt_threat and is_pred_threat:
            fp += 1
            outcome = "FP"
        elif not gt_threat and not is_pred_threat:
            tn += 1
            outcome = "TN"
        else:
            fn += 1
            outcome = "FN"

        # Test PDF generation consistency
        pdf_bytes = generate_email_report(triage)
        assert pdf_bytes.startswith(b"%PDF-"), "Failed to generate consistent PDF report"

        results.append({
            "id": item["id"],
            "category": category,
            "ground_truth_threat": gt_threat,
            "score": score,
            "level": level,
            "prediction": pred,
            "outcome": outcome,
            "pdf_bytes_len": len(pdf_bytes)
        })
        print(f"[{outcome:2}] Score: {score:4.1f} ({level:13}) | Pred: {pred:18} | Category: {category:30}")

    metrics = calculate_binary_metrics(tp, fp, tn, fn)
    print("\n--- Combined Triage Engine Performance Metrics ---")
    print(f"Total Evaluated: {metrics['total']}")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']:.1%})")
    print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']:.1%})")
    print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']:.1%})")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    return {"metrics": metrics, "details": results}


if __name__ == "__main__":
    url_eval = evaluate_url_detection()
    spam_eval = evaluate_email_spam_model()
    pattern_eval = evaluate_email_pattern_analyzer()
    triage_eval = evaluate_combined_triage()
    print("\n=== BENCHMARK EVALUATION COMPLETE ===")
