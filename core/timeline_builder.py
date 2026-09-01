import pandas as pd


def build_timeline(events_df: pd.DataFrame, alerts_df: pd.DataFrame) -> pd.DataFrame:
    timeline_rows = []

    if not events_df.empty:
        for _, row in events_df.iterrows():
            timeline_rows.append(
                {
                    "timestamp": row.get("timestamp", ""),
                    "type": "Event",
                    "source_ip": row.get("source_ip", ""),
                    "username": row.get("username", ""),
                    "description": row.get("normalized_message", ""),
                }
            )

    if not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            timeline_rows.append(
                {
                    "timestamp": row.get("timestamp", ""),
                    "type": "Alert",
                    "source_ip": row.get("source_ip", ""),
                    "username": row.get("username", ""),
                    "description": f"{row.get('severity', '')}: {row.get('description', '')}",
                }
            )

    timeline_df = pd.DataFrame(timeline_rows)

    if not timeline_df.empty:
        timeline_df["timestamp_dt"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
        timeline_df = timeline_df.sort_values("timestamp_dt").drop(columns=["timestamp_dt"])

    return timeline_df
