import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime


def parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M")


def load_logs(filename: str):
    with open(filename, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    required = {"timestamp", "user", "source_ip", "country", "device", "result"}
    missing = required - set(rows[0].keys()) if rows else required
    if missing:
        raise ValueError(f"Missing required columns in CSV: {sorted(missing)}")

    for r in rows:
        r["timestamp_dt"] = parse_ts(r["timestamp"])
        r["hour"] = r["timestamp_dt"].hour
        r["result"] = r["result"].strip().lower()

    rows.sort(key=lambda r: r["timestamp_dt"])
    return rows


def build_baseline(logs):
    """
    Baseline per user:
    - known countries (from successful logins)
    - known devices (from successful logins)
    - typical login hour range (min..max) from successful logins
    """
    baseline = {}
    by_user = defaultdict(list)
    for r in logs:
        by_user[r["user"]].append(r)

    for user, events in by_user.items():
        successes = [e for e in events if e["result"] == "success"]
        countries = {e["country"] for e in successes}
        devices = {e["device"] for e in successes}
        hours = [e["hour"] for e in successes]
        if hours:
            hmin, hmax = min(hours), max(hours)
        else:
            hmin, hmax = 0, 23

        baseline[user] = {
            "countries": countries,
            "devices": devices,
            "hour_min": hmin,
            "hour_max": hmax,
        }
    return baseline


def detect_suspicious_sequences(events):
    """
    Flags success -> failure from same user+ip+device within 10 minutes.
    """
    seq_flags = set()
    for i in range(1, len(events)):
        prev = events[i - 1]
        cur = events[i]
        same_session = (
            prev["user"] == cur["user"]
            and prev["source_ip"] == cur["source_ip"]
            and prev["device"] == cur["device"]
        )
        if same_session:
            delta_min = (cur["timestamp_dt"] - prev["timestamp_dt"]).total_seconds() / 60
            if delta_min <= 10 and prev["result"] == "success" and cur["result"] == "failure":
                seq_flags.add(i)
    return seq_flags


def score_event(event, base):
    reasons = []
    score = 0

    if event["country"] not in base["countries"]:
        score += 40
        reasons.append(f"New country: {event['country']}")

    if event["device"] not in base["devices"]:
        score += 25
        reasons.append(f"New device: {event['device']}")

    if not (base["hour_min"] <= event["hour"] <= base["hour_max"]):
        score += 20
        reasons.append(
            f"Unusual hour: {event['hour']:02d}:00 (baseline {base['hour_min']:02d}-{base['hour_max']:02d})"
        )

    if event["result"] == "failure":
        score += 10
        reasons.append("Login failure")

    return min(score, 100), reasons


def format_text(flagged):
    lines = []
    for item in flagged:
        e = item["event"]
        lines.append("")
        lines.append("🚨 Suspicious Login Event")
        lines.append(f"User       : {e['user']}")
        lines.append(f"Time       : {e['timestamp']}")
        lines.append(f"Country    : {e['country']}")
        lines.append(f"IP Address : {e['source_ip']}")
        lines.append(f"Device     : {e['device']}")
        lines.append(f"Result     : {e['result']}")
        lines.append(f"Risk Score : {item['score']} / 100")
        lines.append("Reasons    :")
        for r in item["reasons"]:
            lines.append(f"  - {r}")
    return "\n".join(lines).strip() + "\n"


def format_json(flagged):
    out = []
    for item in flagged:
        e = item["event"]
        out.append(
            {
                "user": e["user"],
                "timestamp": e["timestamp"],
                "country": e["country"],
                "source_ip": e["source_ip"],
                "device": e["device"],
                "result": e["result"],
                "risk_score": item["score"],
                "reasons": item["reasons"],
            }
        )
    return json.dumps(out, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Suspicious Login Story Builder: baselines login behavior and flags anomalies."
    )
    parser.add_argument("--logfile", default="sample_logins.csv", help="Path to CSV auth logs")
    parser.add_argument(
        "--baseline",
        type=int,
        default=2,
        help="Number of earliest successful logins per run to use as baseline (simple v1 approach)",
    )
    parser.add_argument("--min-score", type=int, default=40, help="Minimum risk score to report")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    print("Suspicious Login Story Builder running locally.")
    logs = load_logs(args.logfile)

    baseline_events = [r for r in logs if r["result"] == "success"][: args.baseline]
    baseline = build_baseline(baseline_events)

    seq_flags = detect_suspicious_sequences(logs)

    flagged = []
    for idx, event in enumerate(logs):
        user = event["user"]
        base = baseline.get(user, {"countries": set(), "devices": set(), "hour_min": 0, "hour_max": 23})
        score, reasons = score_event(event, base)

        if idx in seq_flags:
            score = min(score + 15, 100)
            reasons.append("Suspicious sequence: success → failure (same IP/device within 10m)")

        if score >= args.min_score:
            flagged.append({"event": event, "score": score, "reasons": reasons})

    if not flagged:
        print("✅ No suspicious login events detected.")
        return

    if args.json:
        print(format_json(flagged))
    else:
        print(format_text(flagged))


if __name__ == "__main__":
    main()