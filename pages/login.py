"""
IAM Shield — Sign In Page
Dark cyberpunk aesthetic: #060810 base, #00c8f0 cyan, Rajdhani + Space Mono
Flow:
  Sign In       → app.py              (st.switch_page — main script)
  New User btn  → pages/signup.py  (st.switch_page)
"""

import streamlit as st
import time

st.set_page_config(
    page_title="IAM Shield · Sign In",
    page_icon="🛡",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
[data-testid="collapsedControl"] { display: none; }
#MainMenu { visibility: hidden; }
footer    { visibility: hidden; }
header    { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');

html, body, [class*="css"] { font-family: 'Rajdhani', sans-serif !important; }

.main {
    background-color: #060810;
    background-image:
        radial-gradient(ellipse 70% 55% at 50% 0%,  rgba(0,200,255,0.07) 0%, transparent 65%),
        radial-gradient(ellipse 40% 35% at 80% 80%, rgba(0,100,180,0.05) 0%, transparent 60%),
        linear-gradient(180deg, #060810 0%, #070c16 100%);
    min-height: 100vh;
}

.block-container {
    padding-top: 0 !important;
    padding-bottom: 0 !important;
    max-width: 460px !important;
}

/* Scanlines */
.main::after {
    content: ''; position: fixed; inset: 0;
    background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,0,0,0.025) 2px, rgba(0,0,0,0.025) 4px
    );
    pointer-events: none; z-index: 9999;
}

/* Dot grid */
.main::before {
    content: ''; position: fixed; inset: 0;
    background-image: radial-gradient(circle, rgba(0,200,255,0.055) 1px, transparent 1px);
    background-size: 32px 32px;
    pointer-events: none; z-index: 0;
}

/* Brand */
.login-logo {
    width: 68px; height: 68px;
    background: linear-gradient(135deg, #002e44, #005070);
    border: 1.5px solid rgba(0,200,255,0.45);
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    font-size: 32px;
    box-shadow: 0 0 32px rgba(0,200,255,0.18), inset 0 0 16px rgba(0,200,255,0.08);
    margin: 48px auto 20px auto;
    animation: logo-pulse 3s ease-in-out infinite;
}
@keyframes logo-pulse {
    0%,100% { box-shadow: 0 0 32px rgba(0,200,255,0.18), inset 0 0 16px rgba(0,200,255,0.08); }
    50%      { box-shadow: 0 0 52px rgba(0,200,255,0.32), inset 0 0 24px rgba(0,200,255,0.14); }
}
.login-brand {
    font-family:'Rajdhani',sans-serif; font-size:30px; font-weight:700;
    color:#e4f4ff; letter-spacing:0.12em; text-transform:uppercase;
    text-align:center; margin-bottom:4px;
}
.login-tagline {
    font-family:'Space Mono',monospace; font-size:10.5px; color:#2a6a80;
    letter-spacing:0.18em; text-transform:uppercase;
    text-align:center; margin-bottom:32px;
}

/* Card */
.login-card {
    background: linear-gradient(160deg, #0c1624 0%, #080e1a 100%);
    border: 1px solid rgba(0,200,255,0.13);
    border-radius: 16px;
    padding: 36px 40px 28px 40px;
    box-shadow: 0 0 0 1px rgba(0,200,255,0.04), 0 24px 48px rgba(0,0,0,0.5);
    position: relative; overflow: hidden;
    margin-bottom: 4px;
}
.login-card::before {
    content:''; position:absolute; top:0; left:10%; right:10%; height:1px;
    background: linear-gradient(90deg, transparent, rgba(0,200,255,0.55), transparent);
}
.login-card::after {
    content:''; position:absolute; top:0; right:0; width:60px; height:60px;
    background: linear-gradient(225deg, rgba(0,200,255,0.06) 0%, transparent 70%);
    border-top-right-radius:16px;
}
.card-heading {
    font-family:'Rajdhani',sans-serif; font-size:20px; font-weight:700;
    color:#c8e8f4; letter-spacing:0.06em; text-transform:uppercase; margin-bottom:2px;
}
.card-sub {
    font-family:'Space Mono',monospace; font-size:10px; color:#1e5a70;
    letter-spacing:0.12em; margin-bottom:26px;
}

/* Input labels */
.stTextInput label {
    font-family:'Space Mono',monospace !important; font-size:10px !important;
    letter-spacing:0.16em !important; text-transform:uppercase !important;
    color:#3a7a94 !important; margin-bottom:5px !important;
}

/* Input fields */
.stTextInput > div > div > input {
    background: rgba(0,20,36,0.7) !important;
    border: 1px solid rgba(0,200,255,0.18) !important;
    border-radius: 8px !important;
    color: #c8e8f4 !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 13px !important; padding: 12px 14px !important;
    transition: border-color 0.2s, box-shadow 0.2s !important;
    caret-color: #00c8f0 !important;
}
.stTextInput > div > div > input:focus {
    border-color: rgba(0,200,255,0.5) !important;
    box-shadow: 0 0 0 3px rgba(0,200,255,0.08), 0 0 16px rgba(0,200,255,0.1) !important;
}
.stTextInput > div > div > input::placeholder { color: #1e4a5c !important; }

/* Checkbox */
.stCheckbox > label {
    font-family:'Space Mono',monospace !important; font-size:11px !important;
    color:#3a7a94 !important; letter-spacing:0.06em !important;
}

/* Primary (Sign In) button */
.stButton > button[kind="primary"] {
    font-family:'Rajdhani',sans-serif !important; font-weight:700 !important;
    font-size:15px !important; letter-spacing:0.2em !important;
    text-transform:uppercase !important; width:100% !important; padding:14px !important;
    background: linear-gradient(135deg, #004d6e, #007a9e) !important;
    border: 1px solid rgba(0,200,255,0.4) !important;
    color: #e4f4ff !important; border-radius:8px !important;
    box-shadow: 0 0 24px rgba(0,200,255,0.12) !important;
    margin-top:8px !important; transition: all 0.2s !important;
}
.stButton > button[kind="primary"]:hover {
    background: linear-gradient(135deg, #006080, #009ac4) !important;
    border-color: rgba(0,200,255,0.7) !important;
    box-shadow: 0 0 32px rgba(0,200,255,0.24) !important;
    transform: translateY(-1px) !important;
}

/* Secondary (Create Account) button */
.stButton > button[kind="secondary"] {
    font-family:'Rajdhani',sans-serif !important; font-weight:600 !important;
    font-size:13px !important; letter-spacing:0.14em !important;
    text-transform:uppercase !important; width:100% !important; padding:11px !important;
    background: transparent !important;
    border: 1px solid rgba(0,200,255,0.22) !important;
    color: #00c8f0 !important; border-radius:8px !important;
    box-shadow: none !important; margin-top:0 !important;
    transition: all 0.2s !important;
}
.stButton > button[kind="secondary"]:hover {
    border-color: rgba(0,200,255,0.5) !important;
    background: rgba(0,200,255,0.05) !important;
    box-shadow: 0 0 14px rgba(0,200,255,0.1) !important;
    transform: none !important;
}

/* Divider */
.login-divider { display:flex; align-items:center; gap:12px; margin:20px 0; }
.login-divider-line { flex:1; height:1px; background:rgba(0,200,255,0.08); }
.login-divider-text { font-family:'Space Mono',monospace; font-size:10px; color:#1e4a5c; letter-spacing:0.1em; }

/* SSO */
.sso-row { display:flex; gap:10px; margin-bottom:4px; }
.sso-btn {
    flex:1; display:flex; align-items:center; justify-content:center; gap:8px;
    padding:11px; background:rgba(0,200,255,0.03);
    border:1px solid rgba(0,200,255,0.12); border-radius:8px;
    color:#4a8ea8; font-family:'Rajdhani',sans-serif; font-size:14px; font-weight:600;
    letter-spacing:0.08em; text-transform:uppercase;
    cursor:pointer; transition:all 0.2s; text-decoration:none;
}
.sso-btn:hover { border-color:rgba(0,200,255,0.3); color:#7ac8e0; background:rgba(0,200,255,0.06); }

/* New user row */
.new-user-row {
    display:flex; align-items:center; justify-content:center; gap:8px;
    margin-top:20px; padding-top:18px;
    border-top:1px solid rgba(0,200,255,0.07);
    margin-bottom:10px;
}
.new-user-label {
    font-family:'Space Mono',monospace; font-size:11px; color:#2a5a6e; letter-spacing:0.08em;
}

/* Footer */
.login-footer { display:flex; justify-content:space-between; margin-top:18px; }
.login-link {
    font-family:'Space Mono',monospace; font-size:10px; color:#1e4a5c;
    letter-spacing:0.1em; text-decoration:none; transition:color 0.2s;
}
.login-link:hover { color:#00c8f0; }

/* Security strip */
.security-strip { display:flex; justify-content:center; gap:20px; margin-top:24px; margin-bottom:32px; }
.sec-badge {
    display:flex; align-items:center; gap:5px;
    font-family:'Space Mono',monospace; font-size:9.5px;
    color:#1a4a5c; letter-spacing:0.08em; text-transform:uppercase;
}
.sec-dot { width:5px; height:5px; background:rgba(0,200,255,0.35); border-radius:50%; }

/* Alert */
.stAlert {
    border-radius:8px !important;
    font-family:'Rajdhani',sans-serif !important;
    font-size:14px !important; font-weight:600 !important;
    border-left:3px solid !important;
}
</style>
""", unsafe_allow_html=True)

# ── Session State ─────────────────────────────────────────────────────────────
if "authenticated"  not in st.session_state: st.session_state.authenticated  = False
if "login_attempts" not in st.session_state: st.session_state.login_attempts = 0
if "username"       not in st.session_state: st.session_state.username        = ""

# Already authenticated → go to dashboard immediately
if st.session_state.authenticated:
    st.switch_page("app.py")

# ── Brand block ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="login-logo">🛡</div>
<div class="login-brand">IAM Shield</div>
<div class="login-tagline">Secure Access · CloudTrail Edition · v2.1</div>
""", unsafe_allow_html=True)

# ── Card label (purely decorative — rendered above the form) ──────────────────
st.markdown("""
<div class="login-card">
  <div class="card-heading">Sign In</div>
  <div class="card-sub">ENTER YOUR CREDENTIALS TO ACCESS THE DASHBOARD</div>
</div>
""", unsafe_allow_html=True)

# ── Login form ────────────────────────────────────────────────────────────────
with st.form("login_form", clear_on_submit=False):
    username_input = st.text_input("Username / Email", placeholder="admin@yourorg.com")
    password_input = st.text_input("Password", type="password", placeholder="••••••••••••")

    c_rem, c_forgot = st.columns([1, 1])
    with c_rem:
        st.checkbox("Remember me", value=False)
    with c_forgot:
        st.markdown("""
        <div style="text-align:right;padding-top:6px;">
          <a class="login-link" href="#" style="color:#2a6a80;font-family:'Space Mono',
          monospace;font-size:10px;letter-spacing:0.1em;">FORGOT PASSWORD?</a>
        </div>
        """, unsafe_allow_html=True)

    sign_in_btn = st.form_submit_button(
        "⬡  Sign In", type="primary", use_container_width=True
    )

# ── SSO options ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="login-divider">
  <div class="login-divider-line"></div>
  <div class="login-divider-text">OR CONTINUE WITH</div>
  <div class="login-divider-line"></div>
</div>
<div class="sso-row">
  <a class="sso-btn" href="#">🔑 &nbsp;AWS SSO</a>
  <a class="sso-btn" href="#">🏢 &nbsp;GMAIL/MICROSOFT</a>
</div>
""", unsafe_allow_html=True)

# ── New user section ──────────────────────────────────────────────────────────
st.markdown("""
<div class="new-user-row">
  <span class="new-user-label">New to IAM Shield?</span>
</div>
""", unsafe_allow_html=True)

create_account_btn = st.button(
    "Create an Account  →", key="goto_signup", use_container_width=True
)

# ── Footer & security badges ──────────────────────────────────────────────────
st.markdown("""
<div class="login-footer">
  <a class="login-link" href="#">REQUEST ACCESS</a>
  <a class="login-link" href="#">SECURITY POLICY</a>
  <a class="login-link" href="#">CONTACT ADMIN</a>
</div>
<div class="security-strip">
  <span class="sec-badge"><span class="sec-dot"></span>TLS 1.3</span>
  <span class="sec-badge"><span class="sec-dot"></span>MFA Supported</span>
  <span class="sec-badge"><span class="sec-dot"></span>SOC 2</span>
</div>
""", unsafe_allow_html=True)

# ── Routing: Create Account button ───────────────────────────────────────────
if create_account_btn:
    st.switch_page("pages/signup.py")

# ── Auth logic ────────────────────────────────────────────────────────────────
DEMO_USERS = {
    "admin":             "iam2026",
    "analyst":           "shield123",
    "admin@yourorg.com": "iam2026",
}
MAX_ATTEMPTS = 5

if sign_in_btn:
    if not username_input or not password_input:
        st.error("Please enter both username and password.")
    elif st.session_state.login_attempts >= MAX_ATTEMPTS:
        st.error("🔒  Account locked — too many failed attempts. Contact your administrator.")
    else:
        with st.spinner("Authenticating…"):
            time.sleep(0.7)

        if DEMO_USERS.get(username_input.lower().strip()) == password_input:
            st.session_state.authenticated  = True
            st.session_state.username       = username_input.strip()
            st.session_state.login_attempts = 0
            st.success(f"✓  Welcome back, {username_input}. Loading dashboard…")
            time.sleep(0.5)
            st.switch_page("app.py")         # ← hard redirect to main dashboard
        else:
            st.session_state.login_attempts += 1
            remaining = MAX_ATTEMPTS - st.session_state.login_attempts
            if remaining > 0:
                st.error(f"Invalid credentials. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
            else:
                st.error("🔒  Account locked after too many failed attempts.")