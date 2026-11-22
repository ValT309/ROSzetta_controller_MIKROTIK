def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    parts = []
    for size, unit in ((86400, "д"), (3600, "ч"), (60, "мин"), (1, "с")):
        value, seconds = divmod(seconds, size)
        if value: parts.append(f"{value} {unit}")
    return " ".join(parts) or "0 с"
