<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebGuard — Email Threat Detection</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:     #f0f4fa;
  --surface:#ffffff;
  --navy:   #0b1e4b;
  --blue:   #1d4ed8;
  --blue2:  #2563eb;
  --safe:   #15803d;
  --safebg: #dcfce7;
  --warn:   #92400e;
  --warnbg: #fef3c7;
  --danger: #991b1b;
  --dangerbg:#fee2e2;
  --accent: #0ea5e9;
  --border: #d1daf0;
  --text:   #0b1e4b;
  --muted:  #4b5e8a;
  --dim:    #8898bb;
  --mono:   'IBM Plex Mono',monospace;
  --sans:   'Plus Jakarta Sans',sans-serif;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:var(--sans);background:var(--bg);color:var(--text);
  display:flex;flex-direction:column}

/* ---- Nav ---- */
nav{
  background:var(--navy);
  display:flex;align-items:center;justify-content:space-between;
  padding:0 40px;height:56px;flex-shrink:0;
}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none}
.logo-shield{
  width:28px;height:32px;background:#fff;
  clip-path:polygon(50% 0%,100% 15%,100% 60%,50% 100%,0% 60%,0% 15%);
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
}
.logo-inner{
  width:14px;height:18px;background:var(--blue2);
  clip-path:polygon(50% 0%,100% 15%,100% 60%,50% 100%,0% 60%,0% 15%);
}
.logo-name{font-size:1rem;font-weight:800;color:#fff;letter-spacing:.01em}
.logo-name span{color:#60a5fa}
.nav-tag{font-family:var(--mono);font-size:.65rem;color:#93c5fd;
  border:1px solid #1e40af;padding:3px 10px;border-radius:20px;letter-spacing:.05em}

/* ---- Layout: sidebar + main ---- */
.layout{flex:1;display:flex;overflow:hidden}

/* ---- Sidebar ---- */
.sidebar{
  width:300px;flex-shrink:0;
  background:var(--navy);
  display:flex;flex-direction:column;
  padding:32px 28px;
  gap:28px;
  border-right:1px solid #1e3a7a;
}
.sidebar-title{
  font-size:1.6rem;font-weight:800;color:#fff;line-height:1.2;
}
.sidebar-title span{color:#60a5fa}
.sidebar-sub{font-size:.82rem;color:#94a3b8;line-height:1.6;margin-top:8px}

.cta-stack{display:flex;flex-direction:column;gap:10px}
.cta-btn{
  display:flex;align-items:center;gap:12px;
  padding:14px 16px;border-radius:10px;text-decoration:none;
  transition:background .15s,transform .12s;
}
.cta-btn.primary{background:var(--blue2);color:#fff}
.cta-btn.secondary{background:rgba(255,255,255,.07);color:#e2e8f0;border:1px solid rgba(255,255,255,.1)}
.cta-btn:hover{transform:translateX(3px);opacity:.92}
.cta-icon{
  width:36px;height:36px;border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:16px;flex-shrink:0;
}
.cta-btn.primary .cta-icon{background:rgba(255,255,255,.2)}
.cta-btn.secondary .cta-icon{background:rgba(255,255,255,.1)}
.cta-text h3{font-size:.88rem;font-weight:700}
.cta-text p{font-size:.72rem;opacity:.7;margin-top:2px}

/* Thresholds */
.thresholds{display:flex;flex-direction:column;gap:7px}
.thresh-label{font-family:var(--mono);font-size:.62rem;color:#64748b;
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px}
.thresh-row{
  display:flex;align-items:center;justify-content:space-between;
  background:rgba(255,255,255,.05);border-radius:7px;padding:9px 12px;
}
.thresh-name{font-size:.78rem;font-weight:600}
.thresh-range{font-family:var(--mono);font-size:.68rem;padding:2px 8px;border-radius:10px}
.t-safe  .thresh-name{color:#4ade80} .t-safe  .thresh-range{background:rgba(74,222,128,.15);color:#4ade80}
.t-warn  .thresh-name{color:#fbbf24} .t-warn  .thresh-range{background:rgba(251,191,36,.15);color:#fbbf24}
.t-danger.thresh-name{color:#f87171} .t-danger .thresh-range{background:rgba(248,113,113,.15);color:#f87171}

/* ---- Main content ---- */
.main{flex:1;overflow:hidden;padding:32px 36px;display:flex;flex-direction:column;gap:20px}

.section-head{
  font-family:var(--mono);font-size:.65rem;font-weight:500;
  color:var(--dim);letter-spacing:.1em;text-transform:uppercase;
  margin-bottom:12px;
}

/* Layers grid */
.layers-grid{
  display:grid;grid-template-columns:repeat(4,1fr);gap:12px;
  flex:1;
}
.layer-card{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px 18px;display:flex;flex-direction:column;gap:10px;
  border-top:3px solid var(--blue2);
}
.layer-num{font-family:var(--mono);font-size:.62rem;font-weight:500;
  color:var(--blue2);letter-spacing:.1em}
.layer-name{font-size:.9rem;font-weight:700;color:var(--text)}
.layer-list{list-style:none;display:flex;flex-direction:column;gap:5px;flex:1}
.layer-list li{
  font-size:.75rem;color:var(--muted);line-height:1.5;
  padding-left:14px;position:relative;
}
.layer-list li::before{content:'›';position:absolute;left:0;color:var(--blue2);font-weight:700}
.layer-pts{
  font-family:var(--mono);font-size:.65rem;font-weight:500;
  background:#eff6ff;color:var(--blue);padding:3px 8px;border-radius:6px;
  align-self:flex-start;margin-top:auto;
}

/* Info bar */
.info-bar{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:14px 20px;display:flex;align-items:center;gap:14px;flex-shrink:0;
}
.info-bar .ico{font-size:16px}
.info-bar p{font-size:.78rem;color:var(--muted);line-height:1.5}
.info-bar strong{color:var(--text)}
</style>
</head>
<body>

<nav>
  <a href="<%=request.getContextPath()%>/index" class="logo">
    <div class="logo-shield"><div class="logo-inner"></div></div>
    <span class="logo-name">Web<span>Guard</span></span>
  </a>
  <div class="nav-tag">THREAT INTELLIGENCE v2</div>
</nav>

<div class="layout">

  <aside class="sidebar">
    <div>
      <div class="sidebar-title">Detect phishing<br><span>before it lands.</span></div>
      <div class="sidebar-sub">4-layer analysis combining keyword intelligence, pattern recognition, URL scoring, and VirusTotal verification.</div>
    </div>

    <div class="cta-stack">
      <a href="<%=request.getContextPath()%>/home.jsp" class="cta-btn primary">
        <div class="cta-icon">📧</div>
        <div class="cta-text">
          <h3>Analyse Email</h3>
          <p>Paste text or upload .eml file</p>
        </div>
      </a>
      <a href="<%=request.getContextPath()%>/urlscan.jsp" class="cta-btn secondary">
        <div class="cta-icon">🔗</div>
        <div class="cta-text">
          <h3>Scan a URL</h3>
          <p>7 heuristics + VirusTotal</p>
        </div>
      </a>
    </div>

    <div>
      <div class="thresh-label">Risk thresholds</div>
      <div class="thresholds">
        <div class="thresh-row t-safe">
          <span class="thresh-name t-safe">✓ SAFE</span>
          <span class="thresh-range">Score 0 – 7</span>
        </div>
        <div class="thresh-row t-warn">
          <span class="thresh-name t-warn">⚠ SUSPICIOUS</span>
          <span class="thresh-range">Score 8 – 17</span>
        </div>
        <div class="thresh-row t-danger">
          <span class="thresh-name" style="color:#f87171">🚨 DANGER</span>
          <span class="thresh-range" style="background:rgba(248,113,113,.15);color:#f87171">Score 18 +</span>
        </div>
      </div>
    </div>
  </aside>

  <main class="main">
    <div class="section-head">// detection architecture</div>

    <div class="layers-grid">
      <div class="layer-card">
        <div class="layer-num">LAYER 01</div>
        <div class="layer-name">Keywords + Sender</div>
        <ul class="layer-list">
          <li>Aho-Corasick multi-pattern</li>
          <li>Live Supabase keyword DB</li>
          <li>Inline brand sender check</li>
          <li>Spoofing: +5 pts, trusted: −2 pts</li>
        </ul>
        <div class="layer-pts">0 – 15 pts</div>
      </div>
      <div class="layer-card">
        <div class="layer-num">LAYER 02</div>
        <div class="layer-name">Pattern Analysis</div>
        <ul class="layer-list">
          <li>10+ regex detectors</li>
          <li>Luhn credit-card validation</li>
          <li>Urgency &amp; authority signals</li>
          <li>Excessive CAPS / punctuation</li>
        </ul>
        <div class="layer-pts">0 – 10 pts</div>
      </div>
      <div class="layer-card">
        <div class="layer-num">LAYER 03</div>
        <div class="layer-name">URL Intelligence</div>
        <ul class="layer-list">
          <li>Entropy, IP, TLD, homoglyphs</li>
          <li>30 + brand mismatch check</li>
          <li>VirusTotal for suspicious URLs</li>
          <li>Cumulative score across all URLs</li>
        </ul>
        <div class="layer-pts">0 – 15 pts</div>
      </div>
      <div class="layer-card">
        <div class="layer-num">LAYER 04</div>
        <div class="layer-name">Attachment Scan</div>
        <ul class="layer-list">
          <li>20 + dangerous extensions</li>
          <li>Double-extension detection</li>
          <li>MIME-type mismatch check</li>
          <li>Only scored when present</li>
        </ul>
        <div class="layer-pts">0 – 10 pts</div>
      </div>
    </div>

    <div class="info-bar">
      <span class="ico">ℹ️</span>
      <p><strong>VirusTotal integration</strong> — URLs are submitted only when structural score ≥ 3, protecting the free-tier quota (4 req/min, 500/day). Results show as <strong>"X/Y vendors flagged this URL."</strong> A dangerous attachment always escalates to DANGER regardless of score.</p>
    </div>
  </main>
</div>

</body>
</html>
