<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.phishingdetector.layers.Layer3UrlAnalysis.UrlAnalysisResult" %>
<%@ page import="com.phishingdetector.integrations.VirusTotalUrlReport" %>
<%@ page import="com.phishingdetector.utils.SecurityUtils" %>
<%
    String url             = (String) request.getAttribute("url");
    UrlAnalysisResult ua   = (UrlAnalysisResult) request.getAttribute("urlAnalysis");
    VirusTotalUrlReport vt = (VirusTotalUrlReport) request.getAttribute("vtReport");
    Boolean wasVtScanned   = (Boolean) request.getAttribute("wasVtScanned");
    if (url == null || ua == null) { response.sendRedirect("urlscan.jsp"); return; }
    boolean vtScanned = wasVtScanned != null && wasVtScanned;

    String riskColor, riskBg, riskBorder, riskLabel, riskEmoji;
    if (ua.totalScore >= 10) {
        riskColor="#991b1b"; riskBg="#fee2e2"; riskBorder="#fca5a5"; riskLabel="HIGH RISK"; riskEmoji="🚨";
    } else if (ua.totalScore >= 4) {
        riskColor="#92400e"; riskBg="#fef3c7"; riskBorder="#fcd34d"; riskLabel="SUSPICIOUS"; riskEmoji="⚠";
    } else {
        riskColor="#15803d"; riskBg="#dcfce7"; riskBorder="#86efac"; riskLabel="CLEAN"; riskEmoji="✓";
    }
%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>URL Results — WebGuard</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f0f4fa;--surface:#fff;--navy:#0b1e4b;--blue:#1d4ed8;--blue2:#2563eb;
  --border:#d1daf0;--text:#0b1e4b;--muted:#4b5e8a;--dim:#8898bb;
  --safe:#15803d;--safebg:#dcfce7;--safeborder:#86efac;
  --warn:#92400e;--warnbg:#fef3c7;--warnborder:#fcd34d;
  --danger:#991b1b;--dangerbg:#fee2e2;--dangerborder:#fca5a5;
  --mono:'IBM Plex Mono',monospace;--sans:'Plus Jakarta Sans',sans-serif;
  --risk:<%=riskColor%>;--riskbg:<%=riskBg%>;--riskborder:<%=riskBorder%>;
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
.back-btn{font-family:var(--sans);font-size:.78rem;font-weight:600;
  background:rgba(255,255,255,.12);color:#fff;padding:7px 16px;border-radius:7px;
  text-decoration:none;border:1px solid rgba(255,255,255,.2);transition:background .15s}
.back-btn:hover{background:rgba(255,255,255,.2)}

/* Verdict bar */
.verdict-bar{
  background:var(--riskbg);border-bottom:2px solid var(--riskborder);
  padding:10px 40px;display:flex;align-items:center;gap:20px;flex-shrink:0;
}
.v-badge{font-size:1.1rem;font-weight:800;color:var(--risk);letter-spacing:.02em}
.v-score{font-family:var(--mono);font-size:.78rem;color:var(--risk);opacity:.8}
.v-url{
  font-family:var(--mono);font-size:.72rem;color:var(--risk);
  background:rgba(0,0,0,.05);padding:4px 10px;border-radius:5px;
  word-break:break-all;max-width:600px;opacity:.85;
}

/* Two-column layout */
.layout{flex:1;display:flex;overflow:hidden}

/* Left column: score breakdown */
.scores-col{
  width:280px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);
  padding:20px 18px;display:flex;flex-direction:column;gap:10px;overflow-y:auto;
}
.scores-col::-webkit-scrollbar{width:4px}
.scores-col::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.col-title{font-family:var(--mono);font-size:.62rem;color:var(--dim);
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px}
.score-card{
  display:flex;align-items:center;justify-content:space-between;gap:8px;
  background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:11px 13px;
}
.score-card.hit{background:var(--dangerbg);border-color:var(--dangerborder)}
.sc-label{font-size:.8rem;font-weight:600;color:var(--text)}
.sc-sub{font-size:.67rem;color:var(--muted);margin-top:2px}
.sc-num{font-family:var(--mono);font-size:1.1rem;font-weight:700}
.sc-num.ok{color:var(--safe)} .sc-num.hit{color:var(--danger)}
.total-card{
  display:flex;align-items:center;justify-content:space-between;gap:8px;
  background:var(--riskbg);border:2px solid var(--riskborder);border-radius:10px;
  padding:14px 16px;margin-top:4px;
}
.total-card .sc-label{font-size:.9rem;color:var(--risk)}
.total-card .sc-num{font-size:1.6rem;color:var(--risk)}

/* Right column: issues + VT */
.details-col{flex:1;overflow-y:auto;padding:20px 24px;display:flex;flex-direction:column;gap:16px}
.details-col::-webkit-scrollbar{width:5px}
.details-col::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

.section-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.section-head{
  display:flex;align-items:center;gap:8px;padding:11px 16px;
  border-bottom:1px solid var(--border);background:var(--bg);
  font-size:.8rem;font-weight:700;color:var(--text);
}
.section-head .dot{width:7px;height:7px;border-radius:50%;background:var(--blue2);flex-shrink:0}
.section-head .dot.red{background:var(--danger)} .section-head .dot.green{background:var(--safe)}
.section-body{padding:14px 16px}

.issue-list{display:flex;flex-direction:column;gap:7px}
.issue-item{
  font-size:.78rem;color:var(--danger);
  background:var(--dangerbg);border:1px solid var(--dangerborder);
  border-left:3px solid var(--danger);border-radius:0 7px 7px 0;
  padding:8px 12px;line-height:1.5;
}
.no-issues{font-size:.82rem;color:var(--safe)}

/* VT */
.vt-none{font-size:.82rem;color:var(--muted);line-height:1.6}
.vt-clean{font-size:.82rem;color:var(--safe);line-height:1.6}
.vt-timeout{font-size:.82rem;color:var(--warn);line-height:1.6}
.vt-flagged{background:var(--dangerbg);border:1px solid var(--dangerborder);border-radius:8px;padding:14px}
.vt-flagged-warn{background:var(--warnbg);border:1px solid var(--warnborder);border-radius:8px;padding:14px}
.vt-hl{font-weight:700;font-size:.9rem;margin-bottom:12px}
.vt-hl.mal{color:var(--danger)} .vt-hl.sus{color:var(--warn)}
.vt-stats{display:flex;gap:18px;flex-wrap:wrap}
.vt-stat{text-align:center;min-width:48px}
.vt-n{font-size:1.3rem;font-weight:800;font-family:var(--mono)}
.vt-l{font-size:.62rem;color:var(--muted);margin-top:2px}
.vm .vt-n{color:var(--danger)} .vs .vt-n{color:var(--warn)}
.vh .vt-n{color:var(--safe)}   .vu .vt-n{color:var(--dim)}
.vt-hr{height:1px;background:rgba(0,0,0,.07);margin:12px 0}
.vt-rate{font-family:var(--mono);font-size:.62rem;color:var(--muted)}
</style>
</head>
<body>

<nav>
  <a href="<%=request.getContextPath()%>/index" class="logo">
    <div class="logo-shield"><div class="logo-inner"></div></div>
    <span class="logo-name">Web<span>Guard</span></span>
  </a>
  <a href="urlscan.jsp" class="back-btn">← Scan Another</a>
</nav>

<div class="verdict-bar">
  <div class="v-badge"><%=riskEmoji%> <%=riskLabel%></div>
  <div class="v-score">Score <%=ua.totalScore%></div>
  <div class="v-url"><%=SecurityUtils.escapeHtml(url.length()>80?url.substring(0,80)+"…":url)%></div>
</div>

<div class="layout">

  <aside class="scores-col">
    <div class="col-title">Score Breakdown</div>

    <%
      String[] lbls={"IP Detection","Entropy","Structure","Brand Mismatch","Homoglyph","Path Keywords","TLD Risk"};
      String[] subs={"Raw IP in host","Shannon entropy","Length / encoding","30+ brand check","Punycode / lookalikes","Sensitive path words","Abuse-prone TLD"};
      int[]    vals={ua.ipDetectionScore,ua.entropyScore,ua.structuralScore,ua.brandMismatchScore,ua.homoglyphScore,ua.pathScore,ua.tldScore};
      for(int i=0;i<7;i++){ boolean h=vals[i]>0;
    %>
    <div class="score-card <%=h?"hit":""%>">
      <div><div class="sc-label"><%=lbls[i]%></div><div class="sc-sub"><%=subs[i]%></div></div>
      <div class="sc-num <%=h?"hit":"ok"%>"><%=h?vals[i]:"✓"%></div>
    </div>
    <% } %>

    <div class="total-card">
      <div><div class="sc-label">Total Score</div><div class="sc-sub">of 7 heuristics</div></div>
      <div class="sc-num"><%=ua.totalScore%></div>
    </div>
  </aside>

  <div class="details-col">

    <!-- Issues -->
    <div class="section-card">
      <div class="section-head">
        <div class="dot <%=ua.issues.isEmpty()?"green":"red"%>"></div>
        Issues Detected
        <% if(!ua.issues.isEmpty()){ %>
        <span style="font-family:var(--mono);font-size:.65rem;background:var(--dangerbg);color:var(--danger);
          padding:2px 8px;border-radius:8px;margin-left:auto"><%=ua.issues.size()%></span>
        <% } %>
      </div>
      <div class="section-body">
        <% if(ua.issues.isEmpty()){ %>
        <div class="no-issues">✓ No structural issues detected in this URL.</div>
        <% }else{ %>
        <div class="issue-list">
          <% for(String iss:ua.issues){ %>
          <div class="issue-item"><%=SecurityUtils.escapeHtml(iss)%></div>
          <% } %>
        </div>
        <% } %>
      </div>
    </div>

    <!-- VirusTotal -->
    <div class="section-card">
      <div class="section-head">
        <div class="dot" style="background:#0ea5e9"></div>
        VirusTotal Intelligence
        <% if(vtScanned){ %>
        <span style="font-family:var(--mono);font-size:.62rem;background:#eff6ff;color:var(--blue2);
          padding:2px 8px;border-radius:8px;margin-left:auto">Scanned</span>
        <% } %>
      </div>
      <div class="section-body">
        <% if(!vtScanned){ %>
          <div class="vt-none">ℹ️ Not queried — URL scored below suspicion threshold. No API quota used. Our structural analysis found no significant concerns.</div>
        <% }else if(vt==null){ %>
          <div class="vt-clean">✓ <strong>VirusTotal returned clean.</strong> URL was submitted but no security vendors flagged it. Structural issues above still merit some caution.</div>
        <% }else if("TIMEOUT".equals(vt.verdict)){ %>
          <div class="vt-timeout">⏱️ <strong>Analysis timed out.</strong> The URL was submitted to VirusTotal but didn't complete in time. Try the URL scanner again in a few minutes.</div>
        <% }else{ boolean isMal="MALICIOUS".equals(vt.verdict); %>
          <div class="<%=isMal?"vt-flagged":"vt-flagged-warn"%>">
            <div class="vt-hl <%=isMal?"mal":"sus"%>"><%=isMal?"🚨":"⚠"%> <%=SecurityUtils.escapeHtml(vt.getDisplaySummary())%></div>
            <div class="vt-hr"></div>
            <div class="vt-stats">
              <div class="vt-stat vm"><div class="vt-n"><%=vt.malicious%></div><div class="vt-l">Malicious</div></div>
              <div class="vt-stat vs"><div class="vt-n"><%=vt.suspicious%></div><div class="vt-l">Suspicious</div></div>
              <div class="vt-stat vh"><div class="vt-n"><%=vt.harmless%></div><div class="vt-l">Harmless</div></div>
              <div class="vt-stat vu"><div class="vt-n"><%=vt.undetected%></div><div class="vt-l">Undetected</div></div>
            </div>
            <div class="vt-hr"></div>
            <div class="vt-rate"><%=String.format("%.1f",vt.getDetectionRate())%>% detection rate across <%=vt.getTotalEngines()%> engines</div>
          </div>
        <% } %>
      </div>
    </div>

  </div>
</div>
</body>
</html>
