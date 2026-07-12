<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.phishingdetector.models.EmailAnalysisResult" %>
<%@ page import="com.phishingdetector.integrations.VirusTotalUrlReport" %>
<%@ page import="com.phishingdetector.utils.SecurityUtils" %>
<%@ page import="java.util.List" %>
<%
    EmailAnalysisResult result = (EmailAnalysisResult) request.getAttribute("result");
    if (result == null) { response.sendRedirect("index"); return; }

    String riskColor, riskBg, riskBorder, riskLabel, riskEmoji;
    if ("DANGER".equals(result.riskLevel)) {
        riskColor="#991b1b"; riskBg="#fee2e2"; riskBorder="#fca5a5"; riskLabel="DANGER"; riskEmoji="🚨";
    } else if ("SUSPICIOUS".equals(result.riskLevel)) {
        riskColor="#92400e"; riskBg="#fef3c7"; riskBorder="#fcd34d"; riskLabel="SUSPICIOUS"; riskEmoji="⚠";
    } else {
        riskColor="#15803d"; riskBg="#dcfce7"; riskBorder="#86efac"; riskLabel="SAFE"; riskEmoji="✓";
    }
    int pct = Math.min(100, (int)((result.totalScore*100.0)/50));
%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Analysis Results — WebGuard</title>
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
.new-scan{
  font-family:var(--sans);font-size:.78rem;font-weight:600;
  background:rgba(255,255,255,.12);color:#fff;
  padding:7px 16px;border-radius:7px;text-decoration:none;
  border:1px solid rgba(255,255,255,.2);transition:background .15s;
}
.new-scan:hover{background:rgba(255,255,255,.2)}

/* Verdict bar */
.verdict-bar{
  background:var(--riskbg);border-bottom:2px solid var(--riskborder);
  padding:10px 40px;display:flex;align-items:center;justify-content:space-between;
  flex-shrink:0;gap:20px;
}
.verdict-left{display:flex;align-items:center;gap:16px}
.verdict-badge{display:flex;align-items:center;gap:8px;font-size:1.1rem;font-weight:800;color:var(--risk);letter-spacing:.02em}
.verdict-score{font-family:var(--mono);font-size:.8rem;color:var(--risk);opacity:.8}
.formula{font-family:var(--mono);font-size:.7rem;color:var(--risk);opacity:.7;
  background:rgba(0,0,0,.04);padding:4px 10px;border-radius:5px}
.meter-wrap{display:flex;align-items:center;gap:10px;min-width:220px}
.meter-track{flex:1;height:7px;background:rgba(0,0,0,.1);border-radius:4px;overflow:hidden}
.meter-fill{height:100%;background:var(--risk);border-radius:4px;width:0%;transition:width 1s cubic-bezier(.4,0,.2,1)}
.meter-pct{font-family:var(--mono);font-size:.7rem;color:var(--risk);font-weight:500;min-width:32px;text-align:right}

/* Layout */
.layout{flex:1;display:flex;overflow:hidden}

/* Left: score summary */
.score-panel{
  width:240px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);
  padding:20px 18px;display:flex;flex-direction:column;gap:14px;overflow-y:auto;
}
.score-panel::-webkit-scrollbar{width:4px}
.score-panel::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.score-section-title{font-family:var(--mono);font-size:.6rem;color:var(--dim);
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px}
.score-row{display:flex;align-items:center;justify-content:space-between;gap:8px;
  background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
.score-row-label{font-size:.78rem;font-weight:600;color:var(--text)}
.score-row-sub{font-size:.67rem;color:var(--muted);margin-top:2px}
.score-num{font-family:var(--mono);font-size:1.1rem;font-weight:700;min-width:30px;text-align:right}
.score-num.hi{color:var(--danger)} .score-num.med{color:var(--warn)}
.score-num.ok{color:var(--safe)}   .score-num.na{color:var(--dim);font-size:.75rem}
.meta-block{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px}
.meta-row{display:flex;gap:8px;margin-bottom:7px;font-size:.75rem}
.meta-row:last-child{margin-bottom:0}
.mk{font-family:var(--mono);color:var(--dim);min-width:52px;font-size:.65rem;
  letter-spacing:.04em;padding-top:2px}
.mv{color:var(--text);word-break:break-word;line-height:1.5}
.s-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:.65rem;
  font-weight:500;letter-spacing:.06em;padding:4px 10px;border-radius:6px}
.s-trusted{background:var(--safebg);color:var(--safe);border:1px solid var(--safeborder)}
.s-spoofed{background:var(--dangerbg);color:var(--danger);border:1px solid var(--dangerborder)}
.s-unknown{background:var(--bg);color:var(--muted);border:1px solid var(--border)}

/* Right: tabbed detail pane */
.detail-pane{flex:1;display:flex;flex-direction:column;overflow:hidden}
.tab-bar{display:flex;border-bottom:1px solid var(--border);padding:0 24px;
  background:var(--surface);flex-shrink:0}
.tab{padding:12px 18px;font-size:.8rem;font-weight:600;border:none;background:transparent;
  cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px;
  transition:all .15s}
.tab.active{color:var(--blue2);border-bottom-color:var(--blue2)}
.tab-count{font-family:var(--mono);font-size:.65rem;background:#eff6ff;color:var(--blue2);
  padding:1px 6px;border-radius:8px;margin-left:5px}
.tab-count.warn{background:var(--warnbg);color:var(--warn)}
.tab-count.danger{background:var(--dangerbg);color:var(--danger)}
.tab-panel{display:none;flex:1;overflow-y:auto;padding:18px 24px}
.tab-panel.active{display:block}
.tab-panel::-webkit-scrollbar{width:5px}
.tab-panel::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

/* Keywords */
.pill-wrap{display:flex;flex-wrap:wrap;gap:7px}
.pill{font-family:var(--mono);font-size:.72rem;background:var(--warnbg);
  border:1px solid var(--warnborder);color:var(--warn);padding:4px 10px;border-radius:6px}

/* Flags */
.flag-list{display:flex;flex-direction:column;gap:7px}
.flag-item{display:flex;align-items:flex-start;gap:10px;background:var(--surface);
  border:1px solid var(--border);border-left:3px solid var(--warn);
  border-radius:0 8px 8px 0;padding:10px 14px;font-size:.8rem;color:var(--text);line-height:1.5}
.flag-item.df{border-left-color:var(--danger)}

/* URL cards */
.url-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  margin-bottom:10px;overflow:hidden}
.url-card.sus{border-color:var(--dangerborder)}
.url-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 14px;
  border-bottom:1px solid var(--border);background:var(--bg)}
.url-card.sus .url-head{background:var(--dangerbg)}
.url-str{font-family:var(--mono);font-size:.72rem;color:var(--text);word-break:break-all;flex:1;min-width:0}
.utag{font-family:var(--mono);font-size:.6rem;font-weight:500;letter-spacing:.06em;
  padding:2px 8px;border-radius:10px;flex-shrink:0}
.t-clean{background:var(--safebg);color:var(--safe);border:1px solid var(--safeborder)}
.t-susp{background:var(--dangerbg);color:var(--danger);border:1px solid var(--dangerborder)}
.t-vt{background:#eff6ff;color:var(--blue2);border:1px solid #bfdbfe}
.url-body{padding:12px 14px;font-size:.78rem;color:var(--muted);line-height:1.6}

/* VT results */
.vt-clean{color:var(--safe)} .vt-timeout{color:var(--warn)} .vt-none{color:var(--dim)}
.vt-flagged{background:var(--dangerbg);border:1px solid var(--dangerborder);border-radius:8px;padding:12px 16px}
.vt-flagged-warn{background:var(--warnbg);border:1px solid var(--warnborder);border-radius:8px;padding:12px 16px}
.vt-hl{font-weight:700;font-size:.88rem;margin-bottom:10px}
.vt-hl.mal{color:var(--danger)} .vt-hl.sus{color:var(--warn)}
.vt-stats{display:flex;gap:16px;flex-wrap:wrap}
.vt-stat{text-align:center;min-width:44px}
.vt-n{font-size:1.2rem;font-weight:800} .vt-l{font-family:var(--mono);font-size:.6rem;color:var(--muted);margin-top:2px}
.vm .vt-n{color:var(--danger)} .vs .vt-n{color:var(--warn)} .vh .vt-n{color:var(--safe)} .vu .vt-n{color:var(--dim)}
.vt-hr{height:1px;background:rgba(0,0,0,.07);margin:10px 0}
.vt-rate{font-family:var(--mono);font-size:.62rem;color:var(--muted)}

/* Per-URL issues */
.issue-list{margin-top:8px;display:flex;flex-direction:column;gap:5px}
.issue-item{font-size:.75rem;color:var(--danger);background:var(--dangerbg);
  border-radius:5px;padding:6px 10px}

/* Attachments */
.attach-item{font-family:var(--mono);font-size:.75rem;background:var(--dangerbg);
  border:1px solid var(--dangerborder);border-radius:7px;padding:9px 13px;
  color:var(--danger);margin-bottom:7px}

.empty{color:var(--dim);font-size:.82rem;padding:8px 0}
</style>
</head>
<body>

<nav>
  <a href="<%=request.getContextPath()%>/index" class="logo">
    <div class="logo-shield"><div class="logo-inner"></div></div>
    <span class="logo-name">Web<span>Guard</span></span>
  </a>
  <a href="home.jsp" class="new-scan">+ New Scan</a>
</nav>

<!-- Verdict bar -->
<div class="verdict-bar">
  <div class="verdict-left">
    <div class="verdict-badge"><%=riskEmoji%> <%=riskLabel%></div>
    <div class="verdict-score">Score <%=result.totalScore%> / 50</div>
    <div class="formula">
      L1+Sender(<%=result.layer1Score%>) + L2(<%=result.layer2Score%>) + URLs(<%=result.layer3Score%>)<% if(result.hasAttachments){%> + Attach(<%=result.attachmentScore%>)<%}%> = <%=result.totalScore%>
    </div>
  </div>
  <div class="meter-wrap">
    <div class="meter-track"><div class="meter-fill" id="mFill"></div></div>
    <div class="meter-pct"><%=pct%>%</div>
  </div>
</div>

<div class="layout">

  <!-- Left: score summary -->
  <aside class="score-panel">

    <div>
      <div class="score-section-title">Email Details</div>
      <div class="meta-block">
        <div class="meta-row">
          <span class="mk">From</span>
          <span class="mv"><%=SecurityUtils.escapeHtml(result.from)%></span>
        </div>
        <div class="meta-row">
          <span class="mk">Subject</span>
          <span class="mv"><%=SecurityUtils.escapeHtml(result.subject.length()>60?result.subject.substring(0,60)+"…":result.subject)%></span>
        </div>
      </div>
    </div>

    <div>
      <div class="score-section-title">Layer Scores</div>
      <%
        int s1=result.layer1Score, s2=result.layer2Score, s3=result.layer3Score;
        String c1=s1>=10?"hi":s1>=5?"med":"ok";
        String c2=s2>=8?"hi":s2>=4?"med":"ok";
        String c3=s3>=10?"hi":s3>=5?"med":"ok";
      %>
      <div class="score-row" style="margin-bottom:6px">
        <div><div class="score-row-label">Layer 1</div><div class="score-row-sub">Keywords + Sender</div></div>
        <div class="score-num <%=c1%>"><%=s1%></div>
      </div>
      <div class="score-row" style="margin-bottom:6px">
        <div><div class="score-row-label">Layer 2</div><div class="score-row-sub">Patterns</div></div>
        <div class="score-num <%=c2%>"><%=s2%></div>
      </div>
      <div class="score-row" style="margin-bottom:6px">
        <div><div class="score-row-label">Layer 3</div><div class="score-row-sub">URLs (0–15)</div></div>
        <div class="score-num <%=c3%>"><%=s3%></div>
      </div>
      <div class="score-row">
        <div>
          <div class="score-row-label">Attachments</div>
          <div class="score-row-sub"><%=result.hasAttachments?"Present":"None found"%></div>
        </div>
        <% if(result.hasAttachments){ int sa=result.attachmentScore; String ca=sa>=8?"hi":sa>=4?"med":"ok"; %>
        <div class="score-num <%=ca%>"><%=sa%></div>
        <% }else{ %><div class="score-num na">N/A</div><% } %>
      </div>
    </div>

    <div>
      <div class="score-section-title">Sender Check</div>
      <% String sbC,sbT;
         if(result.senderSpoofed){sbC="s-spoofed";sbT="⚠ Spoofed";}
         else if(result.senderTrusted){sbC="s-trusted";sbT="✓ Verified";}
         else{sbC="s-unknown";sbT="? Unknown";} %>
      <div class="s-badge <%=sbC%>" style="margin-bottom:8px"><%=sbT%></div>
      <% if(!result.senderEmail.isEmpty()){ %>
      <div style="font-size:.72rem;color:var(--muted);word-break:break-all;line-height:1.5">
        <%=SecurityUtils.escapeHtml(result.senderEmail)%>
      </div>
      <% } %>
      <% if(!result.senderReason.isEmpty()){ %>
      <div style="font-size:.7rem;color:var(--dim);margin-top:5px;line-height:1.5">
        <%=SecurityUtils.escapeHtml(result.senderReason)%>
      </div>
      <% } %>
    </div>

    <div style="font-family:var(--mono);font-size:.62rem;color:var(--dim);line-height:1.6;
      background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:10px 12px">
      Thresholds: SAFE &lt; 8 · SUSPICIOUS 8–17 · DANGER ≥ 18
    </div>

  </aside>

  <!-- Right: tabbed details -->
  <div class="detail-pane">
    <div class="tab-bar">
      <button class="tab active" onclick="switchTab('keywords',this)">
        Keywords
        <% if(!result.suspiciousKeywords.isEmpty()){ %><span class="tab-count warn"><%=result.suspiciousKeywords.size()%></span><% } %>
      </button>
      <button class="tab" onclick="switchTab('flags',this)">
        Pattern Flags
        <% if(!result.flags.isEmpty()){ %><span class="tab-count warn"><%=result.flags.size()%></span><% } %>
      </button>
      <button class="tab" onclick="switchTab('urls',this)">
        URLs
        <% if(!result.allUrls.isEmpty()){ %><span class="tab-count <%=result.vtReports.size()>0?"danger":""%>"><%=result.allUrls.size()%></span><% } %>
      </button>
      <% if(result.hasAttachments){ %>
      <button class="tab" onclick="switchTab('attachments',this)">
        Attachments <span class="tab-count danger"><%=result.attachmentFindings.size()%></span>
      </button>
      <% } %>
    </div>

    <!-- Keywords tab -->
    <div class="tab-panel active" id="tab-keywords">
      <% if(result.suspiciousKeywords.isEmpty()){ %>
      <div class="empty">No suspicious keywords matched.</div>
      <% }else{ %>
      <div style="font-family:var(--mono);font-size:.62rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">
        <%=result.suspiciousKeywords.size()%> keyword(s) matched — 2 pts each, max 10 pts from keywords
      </div>
      <div class="pill-wrap">
        <% for(String kw:result.suspiciousKeywords){ %>
        <span class="pill"><%=SecurityUtils.escapeHtml(kw)%></span>
        <% } %>
      </div>
      <% } %>
    </div>

    <!-- Flags tab -->
    <div class="tab-panel" id="tab-flags">
      <% if(result.flags.isEmpty()){ %>
      <div class="empty">No pattern flags triggered.</div>
      <% }else{ %>
      <div class="flag-list">
        <% for(String f:result.flags){
             boolean d=f.toLowerCase().contains("spoof")||f.toLowerCase().contains("danger"); %>
        <div class="flag-item <%=d?"df":""%>"><%=SecurityUtils.escapeHtml(f)%></div>
        <% } %>
      </div>
      <% } %>
    </div>

    <!-- URLs tab -->
    <div class="tab-panel" id="tab-urls">
      <% if(result.allUrls.isEmpty()){ %>
      <div class="empty">No URLs found in email body.</div>
      <% }else{ %>
      <div style="font-family:var(--mono);font-size:.62rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">
        <%=result.allUrls.size()%> total · <%=result.suspiciousUrls.size()%> suspicious · <%=result.vtScannedUrls.size()%> sent to VT · <%=result.vtReports.size()%> flagged by VT
      </div>
      <% for(String u : result.allUrls){
           boolean isSusp  = result.suspiciousUrls.contains(u);
           boolean sentVt  = result.vtScannedUrls.contains(u);
           VirusTotalUrlReport vt = result.vtReports.get(u);
           // FIX: get issues specific to this URL from urlIssuesMap
           List<String> thisUrlIssues = result.urlIssuesMap.get(u);
      %>
      <div class="url-card <%=isSusp?"sus":""%>">
        <div class="url-head">
          <span class="url-str"><%=SecurityUtils.escapeHtml(u)%></span>
          <% if(!isSusp){ %>
            <span class="utag t-clean">CLEAN</span>
          <% }else{ %>
            <span class="utag t-susp">SUSPICIOUS</span>
            <% if(sentVt){ %><span class="utag t-vt">VT SCANNED</span><% } %>
          <% } %>
        </div>
        <div class="url-body">
          <% if(!isSusp){ %>
            <span class="vt-clean">✓ Passed all structural checks. Not submitted to VirusTotal.</span>

          <% }else if(!sentVt){ %>
            <span class="vt-none">Structural score below VT submission threshold (<%=com.phishingdetector.config.Config.URL_SUSPICIOUS_SCORE_THRESHOLD%>). Review structural issues below.</span>

          <% }else if(vt==null){ %>
            <span class="vt-clean">✓ Submitted to VirusTotal — returned clean. No vendors flagged this URL. Structural issues still warrant caution.</span>

          <% }else if("TIMEOUT".equals(vt.verdict)){ %>
            <span class="vt-timeout">⏱ VirusTotal analysis timed out. Try scanning the URL individually in a few minutes.</span>

          <% }else{ boolean isMal="MALICIOUS".equals(vt.verdict); %>
            <div class="<%=isMal?"vt-flagged":"vt-flagged-warn"%>">
              <div class="vt-hl <%=isMal?"mal":"sus"%>">
                <%=isMal?"🚨":"⚠"%> <%=SecurityUtils.escapeHtml(vt.getDisplaySummary())%>
              </div>
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

          <%-- FIX: show issues belonging to THIS URL only, not global list --%>
          <% if(isSusp && thisUrlIssues != null && !thisUrlIssues.isEmpty()){ %>
          <div class="issue-list">
            <% for(int ix=0; ix<thisUrlIssues.size(); ix++){ %>
            <div class="issue-item"><%=SecurityUtils.escapeHtml(thisUrlIssues.get(ix))%></div>
            <% } %>
          </div>
          <% } %>
        </div>
      </div>
      <% } // end for each URL
      } %>
    </div>

    <!-- Attachments tab -->
    <% if(result.hasAttachments){ %>
    <div class="tab-panel" id="tab-attachments">
      <% for(String f:result.attachmentFindings){ %>
      <div class="attach-item"><%=SecurityUtils.escapeHtml(f)%></div>
      <% } %>
    </div>
    <% } %>

  </div>
</div>

<script>
function switchTab(id,btn){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  btn.classList.add('active');
}
window.addEventListener('DOMContentLoaded',()=>{
  setTimeout(()=>{document.getElementById('mFill').style.width='<%=pct%>%'},200);
});
</script>
</body>
</html>
