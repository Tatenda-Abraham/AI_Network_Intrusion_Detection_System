# AI-Based Network Intrusion Detection and Monitoring System (AI-NIDS)
### Chinhoyi University of Technology - Group 5

## Project Overview
A sophisticated wireless intrusion detection system featuring real-time 802.11 frame analysis, machine learning-based anomaly detection, and a dual-mode monitoring dashboard.

## Run Order
1. **Backend Initialization**:
   ```bash
   cd backend
   pip install -r ../requirements.txt
   python app.py
   ```
2. **Frontend Initialization**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
3. **Initial Credentials**:
   - Seeded from `.env` or defaults:
   - **Admin**: `admin` / `CUT_Nids_Admin2026!`
   - **Analyst**: `analyst` / `CUT_Analyst2026!`

## Enabling Monitor Mode
### Windows (Npcap)
1. Install [Npcap](https://npcap.com/) with "Support raw 802.11 traffic (and monitor mode) for wireless adapters" enabled.
2. The system will automatically detect Npcap and allow monitor mode selection on the Capture page.

### Linux (Airmon-ng)
1. Install `aircrack-ng` suite.
2. Put your adapter in monitor mode:
   ```bash
   sudo airmon-ng start wlan0
   ```
3. Use the `wlan0mon` interface in the system.

## Verification Queries
Use these SQL queries in `ai_nids.db` to verify system activity:

```sql
-- View latest login activity
SELECT * FROM login_history ORDER BY event_time DESC LIMIT 50;

-- View latest wireless findings
SELECT * FROM live_findings ORDER BY found_at DESC LIMIT 50;

-- View latest capture windows and anomaly scores
SELECT * FROM live_capture_windows ORDER BY window_start DESC LIMIT 20;

-- Summary of failed login attempts by user
SELECT username, COUNT(*) as failures FROM login_history 
WHERE event_type='LOGIN_FAILED' GROUP BY username;
```

## Security Policies
- **RBAC**: Administrator has full system control; Cybersecurity Analyst can monitor traffic, acknowledge alerts and run the live monitor, but cannot manage users, delete events or read the audit trail.
- **Lockout**: 5 failed attempts results in a 15-minute account lockout.
- **Sessions**: Refresh token rotation with HttpOnly cookies and server-side revocation.
- **Masking**: Cybersecurity Analysts see MAC addresses masked (e.g., `00:11:22:xx:xx:xx`).
