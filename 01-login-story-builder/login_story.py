import csv
from collections import defaultdict

LOG_FILE = "sample_logins.csv"

def load_logs(filename):
    with open(filename, newline="") as f:
        return list(csv.DictReader(f))

def build_baseline(logs):
    baseline = defaultdict(set)
    for log in logs:
        baseline[log["user"]].add(log["country"])
    return baseline

def detect_anomalies(logs, baseline):
    anomalies = []
    for log in logs:
        user = log["user"]
        country = log["country"]
        if country not in baseline[user]:
            anomalies.append(log)
    return anomalies

def build_incident_story(anomalies):
    for event in anomalies:
        print("\n🚨 Suspicious Login Detected")
        print(f"User       : {event['user']}")
        print(f"Time       : {event['timestamp']}")
        print(f"Country    : {event['country']}")
        print(f"IP Address : {event['source_ip']}")
        print(f"Device     : {event['device']}")
        print(f"Result     : {event['result']}")

def main():
    print("Suspicious Login Story Builder running locally.")

    logs = load_logs(LOG_FILE)
    baseline = build_baseline(logs[:2])  # first 2 are "normal"
    anomalies = detect_anomalies(logs[2:], baseline)
    build_incident_story(anomalies)

if __name__ == "__main__":
    main()
