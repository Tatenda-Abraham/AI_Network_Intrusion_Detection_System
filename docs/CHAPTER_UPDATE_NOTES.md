# Chapter Update Notes for AI-NIDS System
### Chinhoyi University of Technology - Group 5

This document lists the exact wording changes and conceptual updates required for the project documentation (Chapters 1-5) based on the latest implementation.

## Chapter 1: Introduction
- **Scope Update**: Mention that the system now focuses on rolling 10-second analysis windows for continuous monitoring rather than single-shot captures.
- **Refresh Interval**: Update mention of dashboard refresh to match the 10-second analysis window (or user-configured value like 5s).

## Chapter 2: Literature Review
- **Wireless Telemetry**: Add section on 802.11 management/control frame analysis using TShark/Npcap.
- **Session Management**: Update security section to include JWT refresh token rotation and server-side session validation.

## Chapter 3: Methodology
- **Pipeline Design**: Describe the rolling window architecture (Capture -> Window Dissection -> Heuristic Analysis -> Database Persistence -> SSE/Polling Update).
- **RBAC Matrix**: Include the full permission matrix defined in `config/permissions.yaml`.

## Chapter 4: System Design
- **Data Dictionary Updates**:
    - Add `login_history`: Tracks all authentication events (success, failure, lockout, revocation).
    - Add `user_sessions`: Stores server-side session state for revocation and rotation.
    - Add `live_capture_windows`: Summarizes 802.11 traffic statistics per 10s window.
    - Add `live_findings`: Stores heuristic-based wireless attack detections.
    - Add `wifi_frames` and `device_conversations`: Stores dissected wireless telemetry.
- **ER Diagram**: Update with new entities and their relationships (e.g., `CaptureSession` -> `LiveCaptureWindow` -> `LiveFinding`).
- **Identity Linking**: Remove references to identity linking and registration number tracking as these were removed in favor of wireless telemetry.

## Chapter 5: Implementation and Testing
- **Testing Tables**: Update with results from `tests/test_security_live.py`.
    - **UT01-UT05**: Unit tests for `WirelessAnalyzer` and `AuthService`.
    - **IT01-IT04**: Integration tests for the full capture-to-dashboard pipeline.
- **Empirical Results**: Include the measured processing latency per 10s window (typically <500ms for 1000 frames).
- **Lockout Verification**: Document the successful enforcement of the 5-failure lockout policy.

## General Terminology Changes
- **"Pretrained Dataset"** -> **"Dashboard Overview"** (historical analysis mode).
- **"Real-time Detection"** -> **"Live Results"** (wireless telemetry mode).
- Remove all mentions of **"Identity Linking"** or **"Registration Number Correlation"**.
