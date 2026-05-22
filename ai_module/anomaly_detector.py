"""
AI Monitoring Module for BlockVerify
Uses rule-based logic + optional Isolation Forest for anomaly detection.
"""

import json
import os
import numpy as np
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    Detects suspicious file activity patterns:
    - Too many modifications in a short time window
    - Modifications outside business hours
    - Multiple failed verifications
    - Rapid successive failures
    """

    BUSINESS_HOURS_START = 8   # 8 AM
    BUSINESS_HOURS_END   = 20  # 8 PM
    MAX_CHANGES_PER_HOUR = 10
    MAX_FAILURES_BEFORE_ALERT = 3
    WINDOW_MINUTES = 60

    def __init__(self, log_path: str = "anomaly_log.json"):
        self.log_path = log_path
        self.events: List[dict] = self._load_log()

    def _load_log(self) -> List[dict]:
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_log(self):
        with open(self.log_path, "w") as f:
            json.dump(self.events, f, indent=2, default=str)

    def log_event(self, file_name: str, event_type: str, success: bool, metadata: dict = None):
        """Record a file event for monitoring."""
        event = {
            "file_name": file_name,
            "event_type": event_type,  # "upload", "verify", "modify"
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        self.events.append(event)
        self._save_log()
        return self.analyze(file_name)

    def analyze(self, file_name: str = None) -> List[dict]:
        """
        Run all anomaly rules. Returns list of detected anomalies.
        If file_name given, filter to that file only.
        """
        anomalies = []
        anomalies.extend(self._check_frequency(file_name))
        anomalies.extend(self._check_off_hours(file_name))
        anomalies.extend(self._check_repeated_failures(file_name))
        anomalies.extend(self._check_ml_anomalies(file_name))
        return anomalies

    def _recent_events(self, file_name: Optional[str], minutes: int = 60) -> List[dict]:
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        events = [
            e for e in self.events
            if datetime.fromisoformat(e["timestamp"]) > cutoff
        ]
        if file_name:
            events = [e for e in events if e["file_name"] == file_name]
        return events

    def _check_frequency(self, file_name: Optional[str]) -> List[dict]:
        """Flag if too many events in a short window."""
        anomalies = []
        recent = self._recent_events(file_name, self.WINDOW_MINUTES)

        # Group by file, ignoring routine background checks to avoid spam
        by_file = defaultdict(list)
        for e in recent:
            if e.get("metadata", {}).get("background"):
                continue
            by_file[e["file_name"]].append(e)

        for fname, evs in by_file.items():
            if len(evs) >= self.MAX_CHANGES_PER_HOUR:
                anomalies.append({
                    "type": "HIGH_FREQUENCY",
                    "severity": "HIGH",
                    "file_name": fname,
                    "count": len(evs),
                    "window_minutes": self.WINDOW_MINUTES,
                    "message": f"'{fname}' had {len(evs)} events in {self.WINDOW_MINUTES} minutes",
                    "timestamp": datetime.utcnow().isoformat()
                })
        return anomalies

    def _check_off_hours(self, file_name: Optional[str]) -> List[dict]:
        """Flag events outside business hours."""
        anomalies = []
        recent = self._recent_events(file_name, 30)
        for e in recent:
            if e.get("metadata", {}).get("background"):
                continue
            hour = datetime.fromisoformat(e["timestamp"]).hour
            if hour < self.BUSINESS_HOURS_START or hour >= self.BUSINESS_HOURS_END:
                anomalies.append({
                    "type": "OFF_HOURS_ACCESS",
                    "severity": "MEDIUM",
                    "file_name": e["file_name"],
                    "hour": hour,
                    "message": f"'{e['file_name']}' accessed at {hour:02d}:00 UTC (outside business hours)",
                    "timestamp": e["timestamp"]
                })
        return anomalies

    def _check_repeated_failures(self, file_name: Optional[str]) -> List[dict]:
        """Flag repeated verification failures."""
        anomalies = []
        recent = self._recent_events(file_name, 120)
        failures = [e for e in recent if not e["success"] and e["event_type"] == "verify"]

        by_file = defaultdict(list)
        for f in failures:
            by_file[f["file_name"]].append(f)

        for fname, fails in by_file.items():
            if len(fails) >= self.MAX_FAILURES_BEFORE_ALERT:
                anomalies.append({
                    "type": "REPEATED_FAILURES",
                    "severity": "CRITICAL",
                    "file_name": fname,
                    "failure_count": len(fails),
                    "message": f"'{fname}' failed verification {len(fails)} times — possible tampering in progress",
                    "timestamp": datetime.utcnow().isoformat()
                })
        return anomalies
        
    def _check_ml_anomalies(self, file_name: Optional[str]) -> List[dict]:
        """Use Isolation Forest ML model to detect irregular event sequences."""
        anomalies = []
        if len(self.events) < 10:
            return anomalies # Not enough data to train reliably
            
        # Extract features for all events (hour of day, day of week, is_success)
        features = []
        target_indices = []
        
        for idx, e in enumerate(self.events):
            dt = datetime.fromisoformat(e["timestamp"])
            features.append([dt.hour, dt.weekday(), 1 if e["success"] else 0])
            if file_name and e["file_name"] == file_name:
                target_indices.append(idx)
            elif not file_name:
                target_indices.append(idx)
                
        if not target_indices:
            return anomalies
            
        X = np.array(features)
        
        # Train Isolation Forest
        clf = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
        try:
            preds = clf.fit_predict(X)
        except Exception:
            return anomalies
            
        # Check if the requested file's recent events are anomalies (-1)
        for idx in target_indices:
            e = self.events[idx]
            # Only alert on recent anomalies to prevent spam
            if preds[idx] == -1 and datetime.fromisoformat(e["timestamp"]) > datetime.utcnow() - timedelta(minutes=15):
                anomalies.append({
                    "type": "ML_ANOMALY_DETECTED",
                    "severity": "MEDIUM",
                    "file_name": e["file_name"],
                    "message": f"ML model detected unusual behavioral pattern for '{e['file_name']}'.",
                    "timestamp": datetime.utcnow().isoformat()
                })
                # Prevent spamming alerts for the same file in rapid succession
                break 
                
        return anomalies

    def get_all_anomalies(self) -> List[dict]:
        return self.analyze()

    def get_stats(self) -> dict:
        total = len(self.events)
        failures = sum(1 for e in self.events if not e["success"])
        uploads = sum(1 for e in self.events if e["event_type"] == "upload")
        verifications = sum(1 for e in self.events if e["event_type"] == "verify")
        return {
            "total_events": total,
            "uploads": uploads,
            "verifications": verifications,
            "failures": failures,
            "anomalies_detected": len(self.get_all_anomalies())
        }
