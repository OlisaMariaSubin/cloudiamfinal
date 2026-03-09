# 🔐 Cloud IAM Over-Permission Detection Tool

**Mini Project | Dept. of CSE | MACE, Kothamangalam**

---

## Project Structure

```
CloudIAM/
├── app.py                   ← Main Streamlit dashboard (run this)
├── requirements.txt
├── modules/
│   ├── log_parser.py        ← Reads real logs from logs/day*_logs.json
│   ├── detection_engine.py  ← Over-permission detection + risk scoring
│   └── anomaly_detector.py  ← Isolation Forest ML anomaly detection
└── logs/
    ├── day1_logs.json       ← Real CloudTrail events (Day 1)
    ├── day2_logs.json       ← Real CloudTrail events (Day 2)
    ├── day3_logs.json       ← Real CloudTrail events (Day 3)
    ├── day4_logs.json       ← Real CloudTrail events (Day 4)
    ├── day5_logs.json       ← Real CloudTrail events (Day 5)
    ├── day6_logs.json       ← Real CloudTrail events (Day 6)
    └── day*.py              ← AWS CLI scripts that generated the logs
```

---

## Setup & Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

Open: `http://localhost:8501`

---

## How the Day Filter Works

The sidebar lets you select which days (1–6) to include in the analysis.
Each day corresponds to a real `logs/day*_logs.json` file covering one day
of CloudTrail activity across 5 IAM users. Changing the selection genuinely
changes the findings — unused permissions, risk scores, and anomaly detection
all update based only on the selected days.

---

## Users

| User | Role |
|---|---|
| olisa-dev | Developer |
| joseph-ops | Operations |
| nayan-analyst | Analyst (Read-Only) |
| jeslin-deployment | CI/CD Deployment |
| danil-admin | Admin |
