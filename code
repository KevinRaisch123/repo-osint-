""
OSINT Toolkit - Educational / Authorized Research Only
A simple Streamlit-based app for legitimate open-source intelligence tasks
focused on infrastructure, domains, and public technical indicators.
"""

import streamlit as st
import whois
import dns.resolver
import requests
import json
import re
from datetime import datetime
from urllib.parse import quote
import socket

# Page config - centered works better on mobile phones
st.set_page_config(
    page_title="OSINT Toolkit (Educational)",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="collapsed"  # collapsed by default = better on iPhone
)

# Custom CSS optimized for mobile (iPhone) + desktop
st.markdown("""
<style>
    /* Mobile-first base */
    .main-header {
        font-size: 1.7rem;
        font-weight: 700;
        color: #1f77b4;
        margin-bottom: 0.15rem;
        line-height: 1.2;
    }
    @media (min-width: 768px) {
        .main-header { font-size: 2.1rem; }
    }
    .disclaimer {
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        padding: 0.85rem;
        margin-bottom: 1.2rem;
        border-radius: 6px;
        color: #856404;
        font-size: 0.9rem;
        line-height: 1.45;
    }
    .success-box {
        background-color: #d4edda;
        border-left: 5px solid #28a745;
        padding: 0.7rem;
        margin: 0.4rem 0;
        border-radius: 4px;
    }
    .info-box {
        background-color: #e7f3ff;
        border-left: 5px solid #2196F3;
        padding: 0.7rem;
        margin: 0.4rem 0;
        border-radius: 4px;
    }
    /* Better tabs on narrow screens */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        flex-wrap: wrap;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 0.4rem 0.7rem;
        font-size: 0.85rem;
    }
    /* Full-width buttons & inputs feel better on touch */
    .stButton > button {
        width: 100%;
        border-radius: 8px;
        padding: 0.55rem 1rem;
        font-weight: 600;
    }
    /* Reduce excessive padding on mobile */
    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 2rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }
    /* Make code blocks wrap on small screens */
    code, pre {
        white-space: pre-wrap !important;
        word-break: break-all;
    }
    /* Sidebar toggle is more accessible */
    section[data-testid="stSidebar"] {
        min-width: 220px;
    }
</style>
""", unsafe_allow_html=True)

# ==================== DISCLAIMER ====================
st.markdown('<p class="main-header">🔍 OSINT Toolkit</p>', unsafe_allow_html=True)
st.caption("Educational tool for authorized cybersecurity research, journalism, and self-investigation • Mobile-friendly")

st.markdown("""
<div class="disclaimer">
<strong>⚠️ ETHICAL & LEGAL DISCLAIMER</strong><br>
This tool collects <strong>only publicly available information</strong>. It is intended strictly for:
<ul>
<li>Authorized penetration testing / defensive security research on assets you own or have permission to test</li>
<li>Investigative journalism and fact-checking</li>
<li>Checking your own digital footprint</li>
<li>Educational purposes and training</li>
</ul>
<strong>Prohibited uses include:</strong> stalking, doxxing, harassment, unauthorized surveillance, identity theft, or any activity that violates laws (including CFAA, GDPR, CCPA, etc.).
<br><br>
<strong>You are solely responsible</strong> for how you use the information obtained. The author accepts no liability for misuse.
</div>
""", unsafe_allow_html=True)

# ==================== HELPER FUNCTIONS ====================

def is_valid_domain(domain: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain.strip().lower()))

def is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_whois(domain: str):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain: str):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            records[rtype] = []
    return records

def get_subdomains_crtsh(domain: str, limit: int = 50):
    """Passive subdomain enumeration via crt.sh (Certificate Transparency)"""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "OSINT-Toolkit-Edu/1.0"})
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            # Clean multi-line and wildcards
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.startswith("*."):
                    line = line[2:]
                if line.endswith(domain) and line != domain:
                    subdomains.add(line)
        sorted_subs = sorted(list(subdomains))[:limit]
        return {"count": len(subdomains), "subdomains": sorted_subs, "limited": len(subdomains) > limit}
    except Exception as e:
        return {"error": str(e)}

def get_ip_info(ip: str):
    """Use free ip-api.com (no key required, rate limited ~45/min)"""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse,mobile,proxy,hosting", timeout=10)
        data = resp.json()
        if data.get("status") == "success":
            return data
        return {"error": data.get("message", "Unknown error")}
    except Exception as e:
        return {"error": str(e)}

def check_username_existence(username: str, platforms: dict):
    """Simple HEAD/GET checks for profile existence on selected public platforms.
    Only reports likely existence based on HTTP status / redirects. No scraping of content.
    """
    results = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Edu-Toolkit/1.0; +research)"}
    for name, url_template in platforms.items():
        url = url_template.format(username=username)
        try:
            # Prefer HEAD, fall back to GET
            resp = requests.head(url, headers=headers, timeout=8, allow_redirects=True)
            if resp.status_code == 405:  # Method not allowed
                resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            # Heuristic: 200 often means exists; 404 means not found
            # Some sites always 200 → mark as "check manually"
            exists = None
            if resp.status_code == 404:
                exists = False
            elif resp.status_code == 200:
                exists = True
            else:
                exists = "unknown"
            results.append({
                "platform": name,
                "url": url,
                "status_code": resp.status_code,
                "exists": exists
            })
        except Exception as e:
            results.append({
                "platform": name,
                "url": url,
                "status_code": None,
                "exists": "error",
                "error": str(e)[:80]
            })
    return results

def generate_dorks(query: str, target_type: str = "domain"):
    """Generate useful Google dork links (opens in new tab)."""
    q = quote(query)
    dorks = []
    if target_type == "domain":
        dorks = [
            ("Site index", f"https://www.google.com/search?q=site%3A{q}"),
            ("Filetypes (PDF)", f"https://www.google.com/search?q=site%3A{q}+filetype%3Apdf"),
            ("Filetypes (DOC/XLS)", f"https://www.google.com/search?q=site%3A{q}+(filetype%3Adoc+OR+filetype%3Axls+OR+filetype%3Adocx)"),
            ("Login / Admin pages", f"https://www.google.com/search?q=site%3A{q}+(inurl%3Alogin+OR+inurl%3Aadmin+OR+inurl%3Asignin)"),
            ("Exposed directories", f"https://www.google.com/search?q=site%3A{q}+intitle%3A%22index+of%22"),
            ("Email addresses", f"https://www.google.com/search?q=%22%40{q}%22"),
            ("Cached pages", f"https://webcache.googleusercontent.com/search?q=cache%3A{q}"),
            ("Related sites", f"https://www.google.com/search?q=related%3A{q}"),
        ]
    else:  # username / general
        dorks = [
            ("Exact username", f"https://www.google.com/search?q=%22{q}%22"),
            ("Social profiles", f"https://www.google.com/search?q=%22{q}%22+(site%3Atwitter.com+OR+site%3Ax.com+OR+site%3Alinkedin.com+OR+site%3Agithub.com)"),
            ("Paste sites", f"https://www.google.com/search?q=%22{q}%22+(site%3Apastebin.com+OR+site%3Agist.github.com)"),
        ]
    return dorks

# ==================== SIDEBAR ====================
with st.sidebar:
    st.header("Navigation")
    st.markdown("Use the tabs on the main page.")
    st.markdown("---")
    st.subheader("Quick Resources")
    st.markdown("""
    - [OSINT Framework](https://osintframework.com/)
    - [Bellingcat Tools](https://www.bellingcat.com/resources/)
    - [crt.sh](https://crt.sh/)
    - [Have I Been Pwned](https://haveibeenpwned.com/)
    - [Shodan](https://www.shodan.io/) (account recommended)
    - [Censys](https://search.censys.io/)
    - [Awesome OSINT (GitHub)](https://github.com/brandonhimpfen/awesome-osint)
    """)
    st.markdown("---")
    st.caption("Built for educational use • " + datetime.now().strftime("%Y-%m-%d"))

# ==================== MAIN TABS ====================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🌐 Domain Recon",
    "📍 IP Lookup",
    "👤 Username Check",
    "🔎 Dork Generator",
    "📚 About & Limits"
])

# ---------- TAB 1: Domain ----------
with tab1:
    st.subheader("Domain Reconnaissance")
    st.markdown("Passive lookups using public WHOIS, DNS, and Certificate Transparency data.")

    domain_input = st.text_input("Enter domain (e.g. example.com)", key="domain_input", placeholder="example.com")
    col_a, col_b = st.columns([1, 3])
    with col_a:
        run_domain = st.button("Run Domain Scan", type="primary", use_container_width=True)

    if run_domain and domain_input:
        domain = domain_input.strip().lower()
        if not is_valid_domain(domain):
            st.error("Please enter a valid domain name (e.g. example.com).")
        else:
            with st.spinner("Gathering public data..."):
                # WHOIS
                st.markdown("### WHOIS Information")
                whois_data = get_whois(domain)
                if isinstance(whois_data, dict) and "error" in whois_data:
                    st.warning(f"WHOIS lookup failed: {whois_data['error']}")
                else:
                    # Display key fields safely
                    fields = {
                        "Domain Name": getattr(whois_data, "domain_name", None),
                        "Registrar": getattr(whois_data, "registrar", None),
                        "Creation Date": getattr(whois_data, "creation_date", None),
                        "Expiration Date": getattr(whois_data, "expiration_date", None),
                        "Updated Date": getattr(whois_data, "updated_date", None),
                        "Name Servers": getattr(whois_data, "name_servers", None),
                        "Status": getattr(whois_data, "status", None),
                        "Emails": getattr(whois_data, "emails", None),
                        "Org": getattr(whois_data, "org", None),
                        "Country": getattr(whois_data, "country", None),
                    }
                    for k, v in fields.items():
                        if v:
                            st.write(f"**{k}:** {v}")

                # DNS
                st.markdown("### DNS Records")
                dns_data = get_dns_records(domain)
                for rtype, values in dns_data.items():
                    if values:
                        st.write(f"**{rtype}:**")
                        for v in values:
                            st.code(v, language=None)

                # Subdomains via crt.sh
                st.markdown("### Subdomains (Certificate Transparency – crt.sh)")
                st.caption("Passive enumeration only. Results may be incomplete or include historical entries.")
                sub_data = get_subdomains_crtsh(domain)
                if "error" in sub_data:
                    st.warning(f"crt.sh query failed: {sub_data['error']}")
                else:
                    st.success(f"Found {sub_data['count']} unique subdomains (showing up to 50)")
                    if sub_data.get("limited"):
                        st.info("Results truncated for display. Full list available via crt.sh directly.")
                    for sub in sub_data["subdomains"]:
                        st.write(f"- `{sub}`")

# ---------- TAB 2: IP ----------
with tab2:
    st.subheader("IP Address Lookup")
    st.markdown("Geolocation, ISP, ASN and basic reputation signals from public sources (ip-api.com).")

    ip_input = st.text_input("Enter IP address (IPv4)", key="ip_input", placeholder="8.8.8.8")
    if st.button("Lookup IP", type="primary"):
        ip = ip_input.strip()
        if not is_valid_ip(ip):
            st.error("Please enter a valid IPv4 address.")
        else:
            with st.spinner("Querying public IP data..."):
                info = get_ip_info(ip)
                if "error" in info:
                    st.error(f"Lookup failed: {info['error']}")
                else:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### Location")
                        st.write(f"**Country:** {info.get('country', 'N/A')}")
                        st.write(f"**Region:** {info.get('regionName', 'N/A')}")
                        st.write(f"**City:** {info.get('city', 'N/A')}")
                        st.write(f"**ZIP:** {info.get('zip', 'N/A')}")
                        st.write(f"**Timezone:** {info.get('timezone', 'N/A')}")
                        if info.get("lat") and info.get("lon"):
                            st.write(f"**Coordinates:** {info['lat']}, {info['lon']}")
                    with col2:
                        st.markdown("#### Network")
                        st.write(f"**ISP:** {info.get('isp', 'N/A')}")
                        st.write(f"**Organization:** {info.get('org', 'N/A')}")
                        st.write(f"**AS:** {info.get('as', 'N/A')}")
                        st.write(f"**Reverse DNS:** {info.get('reverse', 'N/A')}")
                        st.write(f"**Mobile:** {info.get('mobile', False)}")
                        st.write(f"**Proxy:** {info.get('proxy', False)}")
                        st.write(f"**Hosting:** {info.get('hosting', False)}")

# ---------- TAB 3: Username ----------
with tab3:
    st.subheader("Username Existence Check")
    st.markdown("""
    Checks a small set of popular public platforms for the presence of a username by examining HTTP responses.
    **This is not comprehensive** and does not scrape profile content. Many platforms return 200 even for non-existent users or block automated checks.
    Always verify manually. Rate limits and ToS apply.
    """)

    username_input = st.text_input("Username (no @)", key="username_input", placeholder="johndoe")
    platforms = {
        "GitHub": "https://github.com/{username}",
        "Reddit": "https://www.reddit.com/user/{username}",
        "GitLab": "https://gitlab.com/{username}",
        "Hacker News": "https://news.ycombinator.com/user?id={username}",
        "Keybase": "https://keybase.io/{username}",
        "Dev.to": "https://dev.to/{username}",
        "Medium": "https://medium.com/@{username}",
        "Steam": "https://steamcommunity.com/id/{username}",
    }

    if st.button("Check Username", type="primary"):
        uname = username_input.strip()
        if not uname or len(uname) < 2:
            st.error("Enter a valid username (at least 2 characters).")
        elif not re.match(r'^[a-zA-Z0-9_.-]+$', uname):
            st.error("Username contains invalid characters.")
        else:
            with st.spinner("Checking selected platforms (public endpoints only)..."):
                results = check_username_existence(uname, platforms)
                found = [r for r in results if r["exists"] is True]
                not_found = [r for r in results if r["exists"] is False]
                unknown = [r for r in results if r["exists"] not in (True, False)]

                st.markdown(f"### Results for `{uname}`")
                if found:
                    st.success(f"Likely exists on {len(found)} platform(s):")
                    for r in found:
                        st.markdown(f"- **{r['platform']}** → [Open]({r['url']}) (HTTP {r['status_code']})")
                if not_found:
                    st.info(f"Not found (404) on {len(not_found)} platform(s)")
                if unknown:
                    st.warning("Inconclusive (manual verification recommended):")
                    for r in unknown:
                        status = r.get("status_code", "err")
                        st.markdown(f"- **{r['platform']}** → [Open]({r['url']}) (status: {status})")

                st.caption("Note: False positives/negatives are common. Always open the link and verify.")

# ---------- TAB 4: Dorks ----------
with tab4:
    st.subheader("Google Dork Generator")
    st.markdown("Creates ready-to-use Google search links using common advanced operators. Open links in a new tab.")

    dork_query = st.text_input("Target (domain or username/keyword)", key="dork_query", placeholder="example.com or johndoe")
    dork_type = st.radio("Type", ["Domain", "Username / General"], horizontal=True)

    if st.button("Generate Dorks", type="primary") and dork_query:
        ttype = "domain" if dork_type == "Domain" else "general"
        dorks = generate_dorks(dork_query.strip(), ttype)
        st.markdown("### Generated Search Links")
        for title, link in dorks:
            st.markdown(f"- **{title}**: [Open in Google]({link})")

# ---------- TAB 5: About ----------
with tab5:
    st.subheader("About this Toolkit")
    st.markdown("""
    This is a lightweight educational OSINT helper focused on **technical / infrastructure** indicators that are publicly available.

    ### What it does
    - Domain WHOIS + basic DNS records
    - Passive subdomain discovery via Certificate Transparency (crt.sh)
    - IP geolocation & network info (ip-api.com free tier)
    - Limited username existence checks on a few public platforms
    - Google dork link generator

    ### What it intentionally does **not** do
    - Full people search / background checks
    - Scraping private or authenticated data
    - Breach database queries that require API keys
    - Real-time social media monitoring or stalking features
    - Any activity that bypasses access controls

    ### Rate limits & reliability
    - Public endpoints (ip-api, crt.sh, WHOIS) have rate limits and can change.
    - Username checks are heuristic only and frequently inaccurate.
    - No data is stored by this app; everything runs in your session.

    ### Recommendations for real investigations
    Use established frameworks and tools under proper authorization:
    - **theHarvester**, **Amass**, **Subfinder**, **SpiderFoot**
    - **Maltego** (community edition)
    - **OSINT Framework** (https://osintframework.com)
    - Journalistic resources from Bellingcat and GIJN

    Always document your methodology, respect robots.txt / terms of service where applicable, and obtain legal authorization when required.

    ### Using on iPhone / mobile
    This app is mobile-friendly (centered layout, collapsed sidebar, touch-friendly buttons).
    To use it on your iPhone 11:
    1. Deploy the app to a free host (recommended: Streamlit Community Cloud — see README).
    2. Open the public URL in Safari.
    3. Optionally tap the Share button → "Add to Home Screen" for an app-like icon.
    Direct localhost access from a remote computer is not possible; hosting is required.
    """)

    st.info("This app is provided as-is for learning and authorized research. Extend it responsibly.")

# Footer
st.markdown("---")
st.caption("OSINT Toolkit • Educational use only • No warranty • Use at your own risk and in compliance with all applicable laws")
