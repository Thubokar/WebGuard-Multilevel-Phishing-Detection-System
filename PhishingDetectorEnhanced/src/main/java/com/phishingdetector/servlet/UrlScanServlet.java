package com.phishingdetector.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.phishingdetector.config.Config;
import com.phishingdetector.integrations.VirusTotalClient;
import com.phishingdetector.integrations.VirusTotalUrlReport;
import com.phishingdetector.layers.Layer3UrlAnalysis;
import com.phishingdetector.layers.Layer3UrlAnalysis.UrlAnalysisResult;

/**
 * Servlet for standalone URL scanning.
 *
 * NOTE: Do NOT add @WebServlet here – the mapping lives in web.xml only.
 *       Having both causes a duplicate-mapping deployment error on some servers.
 *
 * Requirements addressed:
 *  Req 1 – VT is called only when the URL is structurally suspicious.
 *  Req 4 – VT result forwarded to JSP only when VT actually flags it.
 *  Req 5 – Rate limiting is handled inside VirusTotalClient.
 */
public class UrlScanServlet extends HttpServlet {

    private VirusTotalClient vtClient;
    private Layer3UrlAnalysis layer3;

    @Override
    public void init() throws ServletException {
        vtClient = new VirusTotalClient();
        layer3   = new Layer3UrlAnalysis();
        System.out.println("[URL SCAN] Servlet initialised");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        req.setCharacterEncoding("UTF-8");
        String url = req.getParameter("url");

        if (url == null || url.trim().isEmpty()) {
            req.setAttribute("error", "Please enter a URL to scan");
            req.getRequestDispatcher("/urlscan.jsp").forward(req, resp);
            return;
        }

        url = url.trim();

        // Auto-prepend scheme if user forgot it
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
            url = "https://" + url;
        }

        try {
            // Layer 3 structural / heuristic analysis
            UrlAnalysisResult urlAnalysis = layer3.analyzeUrl(url);

            // VT scan – ONLY if structurally suspicious (Req 1 & 5)
            VirusTotalUrlReport vtReport = null;
            if (urlAnalysis.isSuspicious(Config.URL_SUSPICIOUS_SCORE_THRESHOLD)) {
                try {
                    VirusTotalUrlReport raw = vtClient.scanUrl(url);
                    // Only expose VT result when VT actually flags the URL (Req 4)
                    if (raw != null
                            && ("SUSPICIOUS".equals(raw.verdict)
                                || "MALICIOUS".equals(raw.verdict))) {
                        vtReport = raw;
                    }
                } catch (Exception e) {
                    System.err.println("[URL SCAN] VT scan failed: " + e.getMessage());
                }
            }

            req.setAttribute("url",         url);
            req.setAttribute("urlAnalysis", urlAnalysis);
            req.setAttribute("vtReport",    vtReport);  // null → JSP hides VT section
            req.setAttribute("wasVtScanned",
                    urlAnalysis.isSuspicious(Config.URL_SUSPICIOUS_SCORE_THRESHOLD));
            req.getRequestDispatcher("/urlResult.jsp").forward(req, resp);

        } catch (Exception e) {
            e.printStackTrace();
            req.setAttribute("error", "Error scanning URL: " + e.getMessage());
            req.getRequestDispatcher("/error.jsp").forward(req, resp);
        }
    }
}
