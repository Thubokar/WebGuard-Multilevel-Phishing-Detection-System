<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Analyse Email — WebGuard</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f0f4fa;--surface:#ffffff;--navy:#0b1e4b;--blue:#1d4ed8;--blue2:#2563eb;
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
  text-decoration:none;letter-spacing:.04em;display:flex;align-items:center;gap:6px;
  transition:color .15s}
.back-btn:hover{color:#fff}

.layout{flex:1;display:flex;overflow:hidden}

/* Left info panel */
.info-panel{
  width:260px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);
  padding:28px 24px;display:flex;flex-direction:column;gap:20px;
}
.panel-title{font-size:1rem;font-weight:700;color:var(--text);margin-bottom:4px}
.panel-sub{font-size:.78rem;color:var(--muted);line-height:1.6}
.tip-box{
  background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;
  padding:12px 14px;font-size:.76rem;color:var(--blue);line-height:1.6;
}
.tip-box strong{font-weight:700}
.layer-mini{display:flex;flex-direction:column;gap:6px}
.layer-row{display:flex;align-items:center;gap:8px;font-size:.76rem;color:var(--muted)}
.layer-badge{
  font-family:var(--mono);font-size:.6rem;font-weight:500;
  background:#eff6ff;color:var(--blue2);padding:2px 7px;border-radius:4px;flex-shrink:0;
}

/* Main form area */
.form-area{flex:1;overflow:hidden;padding:28px 36px;display:flex;flex-direction:column}
.page-head{display:flex;align-items:baseline;gap:14px;margin-bottom:20px}
.page-head h1{font-size:1.4rem;font-weight:800;color:var(--text)}
.page-head p{font-size:.8rem;color:var(--muted)}

/* Tabs */
.tab-bar{display:flex;border:1px solid var(--border);border-radius:8px;
  overflow:hidden;margin-bottom:20px;flex-shrink:0;background:var(--bg)}
.tab{flex:1;padding:9px;font-size:.78rem;font-weight:600;border:none;cursor:pointer;
  background:transparent;color:var(--muted);transition:all .15s;letter-spacing:.01em}
.tab.active{background:var(--blue2);color:#fff}

.tab-panel{display:none;flex:1;flex-direction:column;gap:12px;min-height:0}
.tab-panel.active{display:flex}

/* Form fields */
.field{display:flex;flex-direction:column;gap:5px}
.field label{font-family:var(--mono);font-size:.65rem;font-weight:500;
  color:var(--muted);letter-spacing:.08em;text-transform:uppercase}
.field input,.field textarea{
  background:var(--surface);border:1.5px solid var(--border);border-radius:8px;
  padding:10px 13px;font-family:var(--sans);font-size:.85rem;color:var(--text);
  outline:none;transition:border-color .15s,box-shadow .15s;
}
.field textarea{resize:none;flex:1;min-height:0;line-height:1.6}
.field input:focus,.field textarea:focus{
  border-color:var(--blue2);box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.field input::placeholder,.field textarea::placeholder{color:var(--dim)}

/* Fields for manual tab get flexible height */
#tab-manual{flex:1}
#tab-manual .field:last-of-type{flex:1}
#tab-manual .field:last-of-type textarea{flex:1;height:100%}

/* Drop zone */
.drop-zone{
  border:2px dashed var(--border);border-radius:10px;background:var(--bg);
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:8px;flex:1;cursor:pointer;position:relative;transition:border-color .2s,background .2s;
  padding:24px;
}
.drop-zone:hover,.drop-zone.dragover{border-color:var(--blue2);background:#eff6ff}
.drop-zone input[type="file"]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop-icon{font-size:2.2rem}
.drop-text{font-size:.9rem;font-weight:600;color:var(--text)}
.drop-hint{font-family:var(--mono);font-size:.68rem;color:var(--dim)}
.drop-filename{font-family:var(--mono);font-size:.75rem;color:var(--blue2);
  display:none;background:#eff6ff;padding:5px 12px;border-radius:6px;border:1px solid #bfdbfe}

/* Submit row */
.submit-row{display:flex;align-items:center;gap:12px;margin-top:16px;flex-shrink:0}
.submit-btn{
  padding:12px 32px;background:var(--blue2);color:#fff;
  font-family:var(--sans);font-size:.85rem;font-weight:700;
  border:none;border-radius:9px;cursor:pointer;
  transition:background .15s,transform .12s;
}
.submit-btn:hover{background:var(--blue);transform:translateY(-1px)}
.submit-note{font-size:.74rem;color:var(--dim)}

/* Overlay */
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
  <div class="overlay-text">RUNNING ANALYSIS…</div>
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
      <div class="panel-title">Analyse Email</div>
      <div class="panel-sub">Enter email fields manually or upload a .eml file to run the full 4-layer threat analysis.</div>
    </div>
    <div class="tip-box">
      <strong>Tip:</strong> For best results include the From address — it powers the brand sender-mismatch check in Layer 1.
    </div>
    <div>
      <div style="font-family:var(--mono);font-size:.62rem;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-bottom:10px">Layers run</div>
      <div class="layer-mini">
        <div class="layer-row"><span class="layer-badge">L1</span> Keywords + Sender check</div>
        <div class="layer-row"><span class="layer-badge">L2</span> Pattern &amp; regex analysis</div>
        <div class="layer-row"><span class="layer-badge">L3</span> URL heuristics + VirusTotal</div>
        <div class="layer-row"><span class="layer-badge">L4</span> Attachment scan (if any)</div>
      </div>
    </div>
  </aside>

  <main class="form-area">
    <div class="page-head">
      <h1>Email Analysis</h1>
      <p>All layers run automatically</p>
    </div>

    <div class="tab-bar">
      <button class="tab active" onclick="switchTab('manual',this)">Manual Input</button>
      <button class="tab" onclick="switchTab('upload',this)">Upload .eml File</button>
    </div>

    <form action="<%=request.getContextPath()%>/detect" method="post"
          enctype="multipart/form-data" id="form" onsubmit="go()" style="display:flex;flex-direction:column;flex:1;min-height:0">

      <div class="tab-panel active" id="tab-manual">
        <div class="field">
          <label>From</label>
          <input type="text" name="from" placeholder="sender@example.com" autocomplete="off">
        </div>
        <div class="field">
          <label>Subject</label>
          <input type="text" name="subject" placeholder="Email subject line">
        </div>
        <div class="field" style="flex:1;display:flex;flex-direction:column">
          <label>Email Body</label>
          <textarea name="emailBody" placeholder="Paste the full email body here…" style="flex:1"></textarea>
        </div>
      </div>

      <div class="tab-panel" id="tab-upload" style="flex:1">
        <div class="drop-zone" id="dropZone">
          <input type="file" name="emlFile" accept=".eml" id="emlInput" onchange="showFile(this)">
          <div class="drop-icon">📂</div>
          <div class="drop-text">Drop .eml file or click to browse</div>
          <div class="drop-hint">.eml only · max 50 MB</div>
          <div class="drop-filename" id="dropName"></div>
        </div>
      </div>

      <div class="submit-row">
        <button type="submit" class="submit-btn">Run Analysis →</button>
        <span class="submit-note">Usually takes 5–30 seconds depending on URLs found</span>
      </div>
    </form>
  </main>
</div>

<script>
function switchTab(id,btn){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  btn.classList.add('active');
}
function go(){document.getElementById('overlay').classList.add('active')}
function showFile(i){
  if(!i.files.length)return;
  const n=document.getElementById('dropName');
  n.textContent='✓ '+i.files[0].name;n.style.display='block';
}
const dz=document.getElementById('dropZone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('dragover')});
dz.addEventListener('dragleave',()=>dz.classList.remove('dragover'));
dz.addEventListener('drop',e=>{
  e.preventDefault();dz.classList.remove('dragover');
  const f=e.dataTransfer.files[0];
  if(f){const dt=new DataTransfer();dt.items.add(f);
    document.getElementById('emlInput').files=dt.files;
    showFile(document.getElementById('emlInput'));}
});
</script>
</body>
</html>
