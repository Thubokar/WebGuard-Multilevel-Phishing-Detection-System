<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>URL Scanner — WebGuard</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f0f4fa;--surface:#fff;--navy:#0b1e4b;--blue:#1d4ed8;--blue2:#2563eb;
  --border:#d1daf0;--text:#0b1e4b;--muted:#4b5e8a;--dim:#8898bb;
  --mono:'IBM Plex Mono',monospace;--sans:'Plus Jakarta Sans',sans-serif;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:var(--sans);background:var(--bg);color:var(--text);display:flex;flex-direction:column}
nav{background:var(--navy);display:flex;align-items:center;justify-content:space-between;
  padding:0 40px;height:56px;flex-shrink:0}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none}
.logo-shield{width:26px;height:30px;background:#fff;
  clip-path:polygon(50% 0%,100% 15%,100% 60%,50% 100%,0% 60%,0% 15%)}
.logo-inner{width:13px;height:17px;background:var(--blue2);
  clip-path:polygon(50% 0%,100% 15%,100% 60%,50% 100%,0% 60%,0% 15%)}
.logo-name{font-size:1rem;font-weight:800;color:#fff}
.logo-name span{color:#60a5fa}
.back-btn{font-family:var(--mono);font-size:.72rem;color:#93c5fd;
  text-decoration:none;letter-spacing:.04em;transition:color .15s}
.back-btn:hover{color:#fff}

.layout{flex:1;display:flex;overflow:hidden}

.info-panel{
  width:260px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);
  padding:28px 24px;display:flex;flex-direction:column;gap:18px;
}
.panel-title{font-size:1rem;font-weight:700;color:var(--text);margin-bottom:4px}
.panel-sub{font-size:.78rem;color:var(--muted);line-height:1.6}
.check-mini{display:flex;flex-direction:column;gap:7px}
.check-row{
  display:flex;align-items:flex-start;gap:9px;
  background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:9px 11px;
}
.check-dot{width:6px;height:6px;border-radius:50%;background:var(--blue2);flex-shrink:0;margin-top:5px}
.check-text h4{font-size:.75rem;font-weight:700;color:var(--text)}
.check-text p{font-size:.68rem;color:var(--muted);margin-top:2px;line-height:1.4}

.form-area{flex:1;overflow:hidden;padding:28px 36px;display:flex;flex-direction:column}
.page-head{margin-bottom:20px}
.page-head h1{font-size:1.4rem;font-weight:800;color:var(--text);margin-bottom:4px}
.page-head p{font-size:.8rem;color:var(--muted)}

.err-box{background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;
  padding:10px 14px;font-size:.8rem;color:#991b1b;margin-bottom:16px}

.input-row{display:flex;gap:10px;margin-bottom:16px}
.url-input{
  flex:1;background:var(--surface);border:1.5px solid var(--border);border-radius:9px;
  padding:13px 16px;font-family:var(--mono);font-size:.88rem;color:var(--text);
  outline:none;transition:border-color .15s,box-shadow .15s;
}
.url-input:focus{border-color:var(--blue2);box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.url-input::placeholder{color:var(--dim)}
.scan-btn{
  padding:13px 28px;background:var(--blue2);color:#fff;
  font-family:var(--sans);font-size:.85rem;font-weight:700;
  border:none;border-radius:9px;cursor:pointer;white-space:nowrap;
  transition:background .15s,transform .12s;
}
.scan-btn:hover{background:var(--blue);transform:translateY(-1px)}

.checks-label{font-family:var(--mono);font-size:.62rem;color:var(--dim);
  letter-spacing:.08em;text-transform:uppercase;margin-bottom:10px}
.checks-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;flex:1}
.check-card{
  background:var(--surface);border:1px solid var(--border);border-radius:9px;
  padding:13px 14px;display:flex;gap:10px;align-items:flex-start;
}
.check-card .dot{width:7px;height:7px;border-radius:50%;background:var(--blue2);flex-shrink:0;margin-top:5px}
.check-card h4{font-size:.8rem;font-weight:700;color:var(--text);margin-bottom:3px}
.check-card p{font-size:.7rem;color:var(--muted);line-height:1.4}

.overlay{display:none;position:fixed;inset:0;background:rgba(11,30,75,.6);
  z-index:99;align-items:center;justify-content:center;flex-direction:column;gap:16px}
.overlay.active{display:flex}
.spinner{width:44px;height:44px;border:3px solid rgba(255,255,255,.2);
  border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.overlay-text{font-family:var(--mono);font-size:.78rem;color:#fff;letter-spacing:.1em}
</style>
</head>
<body>

<div class="overlay" id="overlay">
  <div class="spinner"></div>
  <div class="overlay-text">SCANNING URL…</div>
</div>

<nav>
  <a href="<%=request.getContextPath()%>/index" class="logo">
    <div class="logo-shield"><div class="logo-inner"></div></div>
    <span class="logo-name">Web<span>Guard</span></span>
  </a>
  <a href="<%=request.getContextPath()%>/index" class="back-btn">← Back to Home</a>
</nav>

<div class="layout">

  <aside class="info-panel">
    <div>
      <div class="panel-title">URL Scanner</div>
      <div class="panel-sub">Check any URL for phishing indicators across 7 structural heuristics before consulting VirusTotal.</div>
    </div>
    <div style="font-family:var(--mono);font-size:.62rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-bottom:-4px">Detection methods</div>
    <div class="check-mini">
      <div class="check-row"><div class="check-dot"></div>
        <div class="check-text"><h4>IP Detection</h4><p>Raw IP in URL — no legitimate service does this</p></div></div>
      <div class="check-row"><div class="check-dot"></div>
        <div class="check-text"><h4>Domain Entropy</h4><p>Shannon entropy detects machine-generated names</p></div></div>
      <div class="check-row"><div class="check-dot"></div>
        <div class="check-text"><h4>Homoglyphs / IDN</h4><p>Cyrillic lookalikes, punycode attacks</p></div></div>
      <div class="check-row"><div class="check-dot"></div>
        <div class="check-text"><h4>VirusTotal</h4><p>90 + vendors — suspicious URLs only</p></div></div>
    </div>
  </aside>

  <main class="form-area">
    <div class="page-head">
      <h1>Scan URL</h1>
      <p>Paste any URL — the scheme (https://) will be added automatically if missing</p>
    </div>

    <% if (request.getAttribute("error") != null) { %>
    <div class="err-box">⚠ <%= request.getAttribute("error") %></div>
    <% } %>

    <form action="<%=request.getContextPath()%>/urlscan" method="post" onsubmit="go()">
      <div class="input-row">
        <input class="url-input" type="text" name="url"
               placeholder="https://suspicious-site.example.com/login"
               value="<%= request.getParameter("url")!=null?request.getParameter("url"):"" %>"
               required autocomplete="off" spellcheck="false">
        <button type="submit" class="scan-btn">Scan →</button>
      </div>
    </form>

    <div class="checks-label">// all 8 checks performed</div>
    <div class="checks-grid">
      <div class="check-card"><div class="dot"></div>
        <div><h4>IP Address</h4><p>Flags direct raw IP in URL host</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>Entropy / Randomness</h4><p>Detects machine-generated domains</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>Brand Impersonation</h4><p>30 + brands with digit-swap variants</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>Homoglyph / Punycode</h4><p>Cyrillic lookalikes and IDN attacks</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>URL Structure</h4><p>Encoding, @, deep subdomains, odd ports</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>Risky TLD</h4><p>25 + abuse-prone TLDs (.tk .xyz .click…)</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>Path Keywords</h4><p>login / verify / passwd / credential</p></div></div>
      <div class="check-card"><div class="dot"></div>
        <div><h4>VirusTotal</h4><p>Real-time check across 90 + vendors</p></div></div>
    </div>
  </main>
</div>

<script>function go(){document.getElementById('overlay').classList.add('active')}</script>
</body>
</html>
