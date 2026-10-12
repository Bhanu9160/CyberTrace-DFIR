from app.forensic.severity_classifier import classify_event

test_events = [
    {
        "EventID": 4625,
        "message": "An account failed to log on"
    },
    {
        "EventID": 4624,
        "message": "An account was successfully logged on"
    },
    {
        "EventID": 4688,
        "message": "Suspicious PowerShell encodedcommand detected"
    },
    {
        "EventID": 1000,
        "message": "Normal system event"
    },
]

for event in test_events:
    print(
        f"Event ID: {event['EventID']} | "
        f"Severity: {classify_event(event)}"
    )