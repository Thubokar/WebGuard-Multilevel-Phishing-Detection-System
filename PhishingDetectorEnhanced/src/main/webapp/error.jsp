<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.phishingdetector.utils.SecurityUtils" %>
<%
    String errorMessage = (String) request.getAttribute("error");
    if (errorMessage == null) errorMessage = "An unknown error occurred.";
%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Error — WebGuard</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f0f4fa;--surface:#fff;--navy:#0b1e4b;--blue2:#2563eb;
  --border:#d1daf0;--text:#0b1e4b;--muted:#4b5e8a;--dim:#8898bb;
  --danger:#991b1b;--dangerbg:#fee2e2;--dangerborder:#fca5a5;
  --safe:#15803d;
  --mono:'IBM Plex Mono',monospace;--sans:'Plus Jakarta Sans',sans-serif;
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:var(--sans);background:var(--bg);color:var(--text);
  display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
nav{background:var(--navy);display:flex;align-items:center;gap:10px;
  padding:0 40px;height:56px;position:fixed;top:0;left:0;right:0}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none}
.logo-shield{width:26px;height:30px;background:#fff;
  clip-path:polygon(50% 0%,100% 15%,100% 60%,50% 100%,0% 60%,0% 15%)}
.logo-inner{width:13px;height:17px;background:var(--blue2);
  clip-path:polygon(50% 0%,100% 15%,100% 60%,50% 100%,0% 60%,0% 15%)}
.logo-name{font-size:1rem;font-weight:800;color:#fff}
.logo-name span{color:#60a5fa}
.card{
  background:var(--surface);border:1px solid var(--dangerborder);border-top:4px solid var(--danger);
  border-radius:14px;padding:40px 44px;max-width:520px;width:100%;text-align:center;
  box-shadow:0 4px 24px rgba(11,30,75,.08);
}
.err-icon{font-size:2.8rem;margin-bottom:16px}
.err-title{font-size:1.4rem;font-weight:800;color:var(--danger);margin-bottom:20px}
.err-msg{
  font-family:var(--mono);font-size:.8rem;color:var(--danger);text-align:left;
  background:var(--dangerbg);border:1px solid var(--dangerborder);
  border-radius:8px;padding:14px 16px;margin-bottom:28px;
  line-height:1.6;word-break:break-word;
}
.btn-row{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.btn{display:inline-block;padding:11px 26px;font-family:var(--sans);font-size:.82rem;
  font-weight:700;text-decoration:none;border-radius:8px;transition:all .15s}
.btn:hover{transform:translateY(-1px)}
.btn-primary{background:var(--blue2);color:#fff}
.btn-primary:hover{background:var(--blue)}
.btn-ghost{background:transparent;border:1.5px solid var(--border);color:var(--muted)}
.btn-ghost:hover{border-color:var(--blue2);color:var(--blue2)}
</style>
</head>
<body>

<nav>
  <a href="<%=request.getContextPath()%>/index" class="logo">
    <div class="logo-shield"><div class="logo-inner"></div></div>
    <span class="logo-name">Web<span>Guard</span></span>
  </a>
</nav>

<div class="card">
  <div class="err-icon">⚠️</div>
  <div class="err-title">Analysis Failed</div>
  <div class="err-msg"><%=SecurityUtils.escapeHtml(errorMessage)%></div>
  <div class="btn-row">
    <a href="home.jsp" class="btn btn-primary">Try Again</a>
    <a href="<%=request.getContextPath()%>/index" class="btn btn-ghost">Back to Home</a>
  </div>
</div>

</body>
</html>
