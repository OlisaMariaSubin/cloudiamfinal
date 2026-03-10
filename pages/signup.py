"""
IAM Shield — Sign Up Page
Matches login.py dark cyberpunk aesthetic exactly.
Flow:
  Submit form → success screen → "Go to Sign In" → login.py
  "Already have an account?" → login.py
"""

import streamlit as st
import time

st.set_page_config(
    page_title="IAM Shield · Create Account",
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

/* ── Canvas ── */
.main {
    background-color: #060810;
    background-image:
        radial-gradient(ellipse 70% 55% at 50% 0%,  rgba(0,200,255,0.07) 0%, transparent 65%),
        radial-gradient(ellipse 40% 35% at 20% 90%, rgba(0,100,180,0.05) 0%, transparent 60%),
        linear-gradient(180deg, #060810 0%, #070c16 100%);
    min-height: 100vh;
}

.block-container {
    padding-top: 0 !important;
    padding-bottom: 0 !important;
    max-width: 520px !important;
}

/* Scanlines */
.main::after {
    content:''; position:fixed; inset:0;
    background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,0,0,0.025) 2px, rgba(0,0,0,0.025) 4px
    );
    pointer-events:none; z-index:9999;
}

/* Dot grid */
.main::before {
    content:''; position:fixed; inset:0;
    background-image: radial-gradient(circle, rgba(0,200,255,0.055) 1px, transparent 1px);
    background-size: 32px 32px;
    pointer-events:none; z-index:0;
}

/* ── Brand ── */
.signup-logo {
    width:64px; height:64px;
    background: linear-gradient(135deg, #002e44, #005070);
    border: 1.5px solid rgba(0,200,255,0.45);
    border-radius:16px;
    display:flex; align-items:center; justify-content:center;
    font-size:30px;
    box-shadow: 0 0 32px rgba(0,200,255,0.18), inset 0 0 16px rgba(0,200,255,0.08);
    margin: 40px auto 18px auto;
    animation: logo-pulse 3s ease-in-out infinite;
}
@keyframes logo-pulse {
    0%,100% { box-shadow: 0 0 32px rgba(0,200,255,0.18), inset 0 0 16px rgba(0,200,255,0.08); }
    50%      { box-shadow: 0 0 52px rgba(0,200,255,0.32), inset 0 0 24px rgba(0,200,255,0.14); }
}
.signup-brand {
    font-family:'Rajdhani',sans-serif; font-size:28px; font-weight:700;
    color:#e4f4ff; letter-spacing:0.12em; text-transform:uppercase;
    text-align:center; margin-bottom:4px;
}
.signup-tagline {
    font-family:'Space Mono',monospace; font-size:10px; color:#2a6a80;
    letter-spacing:0.18em; text-transform:uppercase;
    text-align:center; margin-bottom:28px;
}

/* ── Card ── */
.signup-card {
    background: linear-gradient(160deg, #0c1624 0%, #080e1a 100%);
    border: 1px solid rgba(0,200,255,0.13);
    border-radius: 16px;
    padding: 34px 40px 30px 40px;
    box-shadow: 0 0 0 1px rgba(0,200,255,0.04), 0 24px 48px rgba(0,0,0,0.5);
    position:relative; overflow:hidden;
    margin-bottom:4px;
}
.signup-card::before {
    content:''; position:absolute; top:0; left:10%; right:10%; height:1px;
    background: linear-gradient(90deg, transparent, rgba(0,200,255,0.55), transparent);
}
.signup-card::after {
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
    letter-spacing:0.12em; margin-bottom:24px;
}

/* ── Field labels (Streamlit-injected) ── */
.stTextInput label, .stSelectbox label, .stRadio label {
    font-family:'Space Mono',monospace !important; font-size:10px !important;
    letter-spacing:0.16em !important; text-transform:uppercase !important;
    color:#3a7a94 !important; margin-bottom:5px !important;
}

/* ── Input fields ── */
.stTextInput > div > div > input {
    background: rgba(0,20,36,0.7) !important;
    border: 1px solid rgba(0,200,255,0.18) !important;
    border-radius: 8px !important; color:#c8e8f4 !important;
    font-family:'Space Mono',monospace !important; font-size:13px !important;
    padding:12px 14px !important; caret-color:#00c8f0 !important;
    transition: border-color 0.2s, box-shadow 0.2s !important;
}
.stTextInput > div > div > input:focus {
    border-color: rgba(0,200,255,0.5) !important;
    box-shadow: 0 0 0 3px rgba(0,200,255,0.08), 0 0 16px rgba(0,200,255,0.1) !important;
}
.stTextInput > div > div > input::placeholder { color:#1e4a5c !important; }

/* ── Select / multiselect ── */
.stSelectbox > div > div {
    background: rgba(0,20,36,0.7) !important;
    border: 1px solid rgba(0,200,255,0.18) !important;
    border-radius:8px !important; color:#c8e8f4 !important;
    font-family:'Rajdhani',sans-serif !important;
}

/* ── Radio ── */
.stRadio > div { gap: 8px !important; }
.stRadio > div > label {
    background: rgba(0,20,36,0.5) !important;
    border: 1px solid rgba(0,200,255,0.14) !important;
    border-radius:8px !important; padding:10px 14px !important;
    color:#7aa8be !important; font-family:'Rajdhani',sans-serif !important;
    font-size:14px !important; font-weight:600 !important;
    transition: border-color 0.2s, background 0.2s !important;
    cursor:pointer !important;
}
.stRadio > div > label:hover {
    border-color: rgba(0,200,255,0.35) !important;
    background: rgba(0,200,255,0.06) !important;
}
.stRadio > div > label[data-checked="true"] {
    border-color: rgba(0,200,255,0.55) !important;
    background: rgba(0,200,255,0.08) !important;
    color:#c8e8f4 !important;
}

/* ── Checkbox ── */
.stCheckbox > label {
    font-family:'Space Mono',monospace !important; font-size:11px !important;
    color:#3a7a94 !important; letter-spacing:0.06em !important;
}

/* ── Plan section label ── */
.plan-label {
    font-family:'Space Mono',monospace; font-size:10px; color:#3a7a94;
    letter-spacing:0.16em; text-transform:uppercase; margin:16px 0 8px 0;
}

/* Plan cards rendered via HTML */
.plan-grid { display:flex; gap:8px; margin-bottom:16px; }
.plan-card {
    flex:1; padding:12px 14px;
    background: rgba(0,20,36,0.5);
    border: 1px solid rgba(0,200,255,0.14);
    border-radius:10px; cursor:pointer;
    transition: border-color 0.2s, background 0.2s;
}
.plan-card.recommended {
    border-color: rgba(0,200,255,0.45);
    background: rgba(0,200,255,0.06);
}
.plan-name {
    font-family:'Rajdhani',sans-serif; font-size:15px; font-weight:700;
    color:#c8e8f4; margin-bottom:2px;
}
.plan-price {
    font-family:'Space Mono',monospace; font-size:11px; color:#00c8f0;
}
.plan-desc {
    font-family:'Rajdhani',sans-serif; font-size:12px; color:#4a7a90; margin-top:4px;
}
.plan-badge {
    font-family:'Space Mono',monospace; font-size:9px; color:#00c8f0;
    background: rgba(0,200,255,0.1); border:1px solid rgba(0,200,255,0.2);
    border-radius:3px; padding:2px 6px; float:right;
}

/* ── Submit button (primary) ── */
.stButton > button[kind="primary"] {
    font-family:'Rajdhani',sans-serif !important; font-weight:700 !important;
    font-size:15px !important; letter-spacing:0.2em !important;
    text-transform:uppercase !important; width:100% !important; padding:14px !important;
    background: linear-gradient(135deg, #004d6e, #007a9e) !important;
    border: 1px solid rgba(0,200,255,0.4) !important;
    color:#e4f4ff !important; border-radius:8px !important;
    box-shadow: 0 0 24px rgba(0,200,255,0.12) !important;
    margin-top:8px !important; transition:all 0.2s !important;
}
.stButton > button[kind="primary"]:hover {
    background: linear-gradient(135deg, #006080, #009ac4) !important;
    border-color: rgba(0,200,255,0.7) !important;
    box-shadow: 0 0 32px rgba(0,200,255,0.24) !important;
    transform: translateY(-1px) !important;
}

/* ── Secondary (back) button ── */
.stButton > button[kind="secondary"] {
    font-family:'Rajdhani',sans-serif !important; font-weight:600 !important;
    font-size:13px !important; letter-spacing:0.14em !important;
    text-transform:uppercase !important; width:100% !important; padding:11px !important;
    background:transparent !important;
    border: 1px solid rgba(0,200,255,0.2) !important;
    color:#00c8f0 !important; border-radius:8px !important;
    box-shadow:none !important; margin-top:0 !important;
    transition:all 0.2s !important;
}
.stButton > button[kind="secondary"]:hover {
    border-color: rgba(0,200,255,0.5) !important;
    background: rgba(0,200,255,0.05) !important;
    box-shadow: 0 0 14px rgba(0,200,255,0.1) !important;
}

/* ── Already have account row ── */
.already-row {
    display:flex; align-items:center; justify-content:center;
    gap:8px; margin-top:20px; padding-top:18px;
    border-top: 1px solid rgba(0,200,255,0.07);
    margin-bottom:10px;
}
.already-label {
    font-family:'Space Mono',monospace; font-size:11px; color:#2a5a6e;
    letter-spacing:0.08em;
}

/* ── Footer & security ── */
.signup-footer { display:flex; justify-content:space-between; margin-top:18px; }
.signup-link {
    font-family:'Space Mono',monospace; font-size:10px; color:#1e4a5c;
    letter-spacing:0.1em; text-decoration:none; transition:color 0.2s;
}
.signup-link:hover { color:#00c8f0; }
.security-strip { display:flex; justify-content:center; gap:20px; margin-top:22px; margin-bottom:32px; }
.sec-badge {
    display:flex; align-items:center; gap:5px;
    font-family:'Space Mono',monospace; font-size:9.5px;
    color:#1a4a5c; letter-spacing:0.08em; text-transform:uppercase;
}
.sec-dot { width:5px; height:5px; background:rgba(0,200,255,0.35); border-radius:50%; }

/* ── Alert ── */
.stAlert {
    border-radius:8px !important; font-family:'Rajdhani',sans-serif !important;
    font-size:14px !important; font-weight:600 !important; border-left:3px solid !important;
}

/* ── Success state ── */
.success-wrap {
    text-align:center; padding:60px 32px 40px 32px;
    background: linear-gradient(160deg, #0c1624, #080e1a);
    border: 1px solid rgba(0,200,255,0.13);
    border-radius:16px; margin:40px 0;
    box-shadow: 0 0 0 1px rgba(0,200,255,0.04), 0 24px 48px rgba(0,0,0,0.5);
    position:relative; overflow:hidden;
}
.success-wrap::before {
    content:''; position:absolute; top:0; left:10%; right:10%; height:1px;
    background: linear-gradient(90deg, transparent, rgba(0,200,255,0.55), transparent);
}
.success-icon {
    font-size:52px; margin-bottom:20px;
    animation: bounce-in 0.5s cubic-bezier(0.34,1.56,0.64,1) both;
}
@keyframes bounce-in {
    from { transform:scale(0.3); opacity:0; }
    to   { transform:scale(1);   opacity:1; }
}
.success-title {
    font-family:'Rajdhani',sans-serif; font-size:26px; font-weight:700;
    color:#e4f4ff; letter-spacing:0.1em; text-transform:uppercase; margin-bottom:10px;
}
.success-sub {
    font-family:'Space Mono',monospace; font-size:11px; color:#2a6a80;
    letter-spacing:0.08em; line-height:1.8; margin-bottom:28px;
}
.success-detail {
    display:inline-flex; align-items:center; gap:8px;
    background:rgba(0,200,255,0.05); border:1px solid rgba(0,200,255,0.15);
    border-radius:8px; padding:10px 18px; margin-bottom:28px;
    font-family:'Space Mono',monospace; font-size:11px; color:#4a8ea8;
}
</style>
""", unsafe_allow_html=True)

# ── Session State ─────────────────────────────────────────────────────────────
if "signup_done"  not in st.session_state: st.session_state.signup_done  = False
if "signup_name"  not in st.session_state: st.session_state.signup_name  = ""
if "signup_email" not in st.session_state: st.session_state.signup_email = ""
if "signup_plan"  not in st.session_state: st.session_state.signup_plan  = ""

# ══════════════════════════════════════════════════════════════════════════════
# SUCCESS SCREEN
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.signup_done:
    first = st.session_state.signup_name.split()[0] if st.session_state.signup_name else "there"

    st.markdown(f"""
    <div class="signup-logo">🛡</div>
    <div class="success-wrap">
      <div class="success-icon">✅</div>
      <div class="success-title">Welcome Aboard, {first}!</div>
      <div class="success-sub">
        YOUR ACCOUNT HAS BEEN CREATED SUCCESSFULLY.<br>
        A CONFIRMATION EMAIL HAS BEEN DISPATCHED.
      </div>
      <div class="success-detail">
        📧 &nbsp; {st.session_state.signup_email}
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("⬡  Sign In to Dashboard", type="primary", use_container_width=True):
            st.session_state.signup_done = False
            st.switch_page("pages/login.py")

    st.markdown("""
    <div class="security-strip">
      <span class="sec-badge"><span class="sec-dot"></span>Account Secured</span>
      <span class="sec-badge"><span class="sec-dot"></span>MFA Recommended</span>
      <span class="sec-badge"><span class="sec-dot"></span>SOC 2</span>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ══════════════════════════════════════════════════════════════════════════════
# SIGNUP FORM
# ══════════════════════════════════════════════════════════════════════════════

# ── Brand ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="signup-logo">🛡</div>
<div class="signup-brand">IAM Shield</div>
<div class="signup-tagline">Create Your Account · CloudTrail Edition</div>
""", unsafe_allow_html=True)

# ── Card heading ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="signup-card">
  <div class="card-heading">Create Account</div>
  <div class="card-sub">FILL IN YOUR DETAILS TO GET STARTED WITH IAM SHIELD</div>
</div>
""", unsafe_allow_html=True)

# ── Form ──────────────────────────────────────────────────────────────────────
with st.form("signup_form", clear_on_submit=False):

    # Name row
    n1, n2 = st.columns(2)
    with n1:
        first_name = st.text_input("First Name", placeholder="Jane")
    with n2:
        last_name = st.text_input("Last Name", placeholder="Smith")

    # Work email + company
    email   = st.text_input("Work Email", placeholder="jane@yourorg.com")
    company = st.text_input("Organisation / Company", placeholder="Acme Security Corp")

    # Role selectbox
    role = st.selectbox("Your Role", [
        "Select a role…",
        "Security Engineer",
        "Cloud Architect",
        "DevOps / Platform Engineer",
        "Compliance / GRC Analyst",
        "IT Administrator",
        "CISO / Security Manager",
        "Developer",
        "Other",
    ])

    # Password
    p1, p2 = st.columns(2)
    with p1:
        password = st.text_input("Password", type="password", placeholder="Min. 8 characters")
    with p2:
        confirm  = st.text_input("Confirm Password", type="password", placeholder="Repeat password")

    # Plan picker
    st.markdown('<div class="plan-label">Plan</div>', unsafe_allow_html=True)
    plan = st.radio(
        "Plan",
        ["Starter — Free · Up to 5 users",
         "Professional — $49/mo · Up to 25 users",
         "Enterprise — Custom pricing · Unlimited"],
        index=1,
        label_visibility="collapsed",
    )

    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    terms   = st.checkbox("I agree to the Terms of Service and Privacy Policy")
    updates = st.checkbox("Send me product updates and security advisories (optional)", value=True)

    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    submitted = st.form_submit_button(
        "⬡  Create My Account", type="primary", use_container_width=True
    )

# ── "Already have an account?" section ───────────────────────────────────────
st.markdown("""
<div class="already-row">
  <span class="already-label">Already have an account?</span>
</div>
""", unsafe_allow_html=True)

back_to_login = st.button("Sign In →", use_container_width=True, key="back_login")

st.markdown("""
<div class="signup-footer">
  <a class="signup-link" href="#">TERMS OF SERVICE</a>
  <a class="signup-link" href="#">PRIVACY POLICY</a>
  <a class="signup-link" href="#">CONTACT ADMIN</a>
</div>
<div class="security-strip">
  <span class="sec-badge"><span class="sec-dot"></span>TLS 1.3</span>
  <span class="sec-badge"><span class="sec-dot"></span>SOC 2 Compliant</span>
  <span class="sec-badge"><span class="sec-dot"></span>GDPR Ready</span>
</div>
""", unsafe_allow_html=True)

# ── Routing: back to login ────────────────────────────────────────────────────
if back_to_login:
    st.switch_page("pages/login.py")

# ── Form validation & submission ──────────────────────────────────────────────
if submitted:
    errors = []
    if not first_name.strip() or not last_name.strip():
        errors.append("Please enter your full name.")
    if not email.strip() or "@" not in email or "." not in email.split("@")[-1]:
        errors.append("Please enter a valid work email address.")
    if not company.strip():
        errors.append("Organisation name is required.")
    if role == "Select a role…":
        errors.append("Please select your role.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != confirm:
        errors.append("Passwords do not match.")
    if not terms:
        errors.append("You must accept the Terms of Service to continue.")

    if errors:
        for err in errors:
            st.error(f"⚠  {err}")
    else:
        with st.spinner("Creating your account…"):
            time.sleep(1.0)   # simulate API call

        # Store for success screen
        st.session_state.signup_name  = f"{first_name.strip()} {last_name.strip()}"
        st.session_state.signup_email = email.strip()
        st.session_state.signup_plan  = plan.split(" — ")[0]
        st.session_state.signup_done  = True
        st.rerun()