def classify_event(event):
    """
    Assign a severity level to a Windows event.
    Returns: Critical, High, Medium, Low, or Informational.
    """

    event_id = str(
        event.get("event_id", event.get("EventID", event.get("EventCode", "")))
    )

    message = str(
        event.get("message", event.get("Message", event.get("description", "")))
    ).lower()

    combined = f"{event_id} {message}"

    # Critical: strong indicators that require immediate investigation.
    if any(term in combined for term in [
        "ransomware",
        "credential dumping",
        "malware detected",
        "security log cleared",
    ]):
        return "Critical"

    # High: potentially suspicious activity.
    if event_id == "4625" and any(term in combined for term in [
        "multiple failed",
        "brute force",
        "repeated failed",
    ]):
        return "High"

    if any(term in combined for term in [
        "mimikatz",
        "encodedcommand",
        "encoded command",
        "suspicious powershell",
        "unauthorized access",
    ]):
        return "High"

    # Medium: individual failed logins or potentially unusual activity.
    if event_id == "4625":
        return "Medium"

    if any(term in combined for term in [
        "privilege escalation",
        "account locked",
        "unusual login",
    ]):
        return "Medium"

    # Low: noteworthy events that are not clearly suspicious.
    if any(term in combined for term in [
        "service stopped",
        "service started",
        "process created",
    ]):
        return "Low"

    # Informational: normal successful logins.
    if event_id == "4624":
        return "Informational"

    return "Low"