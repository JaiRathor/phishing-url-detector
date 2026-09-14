/**
 * PhishShield Web Client — URL Threat Analyzer
 * Communicates with Node.js Express REST API (/api/analyze)
 */

document.addEventListener("DOMContentLoaded", function () {
  const API_ENDPOINT = "/api/analyze";

  const analyzerForm = document.getElementById("analyzerForm");
  const urlInput = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const sampleChips = document.querySelectorAll(".chip[data-sample]");

  const loadingCard = document.getElementById("loadingCard");
  const resultsCard = document.getElementById("resultsCard");
  const errorCard = document.getElementById("errorCard");
  const errorTitle = document.getElementById("errorTitle");
  const errorMessage = document.getElementById("errorMessage");

  const analyzedUrlDisplay = document.getElementById("analyzedUrlDisplay");
  const riskBadge = document.getElementById("riskBadge");
  const riskIcon = document.getElementById("riskIcon");
  const riskLevelText = document.getElementById("riskLevelText");
  const riskScoreNumber = document.getElementById("riskScoreNumber");
  const gaugeFill = document.getElementById("gaugeFill");

  const indProtocol = document.getElementById("indProtocol");
  const indDomainType = document.getElementById("indDomainType");
  const indTriggerCount = document.getElementById("indTriggerCount");
  const reasonsContainer = document.getElementById("reasonsContainer");

  // Toggle clear input button visibility
  if (urlInput) {
    urlInput.addEventListener("input", function () {
      if (clearBtn) {
        if (this.value.trim()) {
          clearBtn.classList.remove("hidden");
        } else {
          clearBtn.classList.add("hidden");
        }
      }
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      if (urlInput) {
        urlInput.value = "";
        urlInput.focus();
      }
      clearBtn.classList.add("hidden");
    });
  }

  // Sample URL quick-click handler
  sampleChips.forEach((chip) => {
    chip.addEventListener("click", function (e) {
      e.preventDefault();
      const sampleUrl = this.getAttribute("data-sample");
      if (sampleUrl && urlInput) {
        urlInput.value = sampleUrl;
        if (clearBtn) clearBtn.classList.remove("hidden");
        runScan(sampleUrl);
      }
    });
  });

  // Form submission handler
  if (analyzerForm) {
    analyzerForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const val = urlInput ? urlInput.value.trim() : "";
      if (val) {
        runScan(val);
      } else {
        showError(
          "Input Required",
          "Please enter a valid website URL to analyze.",
        );
      }
    });
  }

  function hideError() {
    if (errorCard) errorCard.classList.add("hidden");
  }

  function showError(title, msg) {
    if (loadingCard) loadingCard.classList.add("hidden");
    if (resultsCard) resultsCard.classList.add("hidden");
    if (errorTitle) errorTitle.textContent = title || "Analysis Failed";
    if (errorMessage)
      errorMessage.textContent = msg || "An unexpected error occurred.";
    if (errorCard) errorCard.classList.remove("hidden");
  }

  function setLoading(isLoading) {
    if (isLoading) {
      hideError();
      if (resultsCard) resultsCard.classList.add("hidden");
      if (loadingCard) loadingCard.classList.remove("hidden");
      if (analyzeBtn) analyzeBtn.disabled = true;
      if (urlInput) urlInput.disabled = true;
    } else {
      if (loadingCard) loadingCard.classList.add("hidden");
      if (analyzeBtn) analyzeBtn.disabled = false;
      if (urlInput) urlInput.disabled = false;
    }
  }

  async function runScan(urlStr) {
    setLoading(true);

    try {
      const response = await fetch(API_ENDPOINT, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: urlStr }),
      });

      const data = await response.json();

      if (!response.ok || !data.valid) {
        const msg =
          data.error || `HTTP ${response.status}: ${response.statusText}`;
        showError("Validation Error", msg);
        return;
      }

      renderResults(data);
    } catch (err) {
      console.error("API connection error:", err);
      showError(
        "Connection Refused",
        "Cannot connect to PhishShield API backend at /api/analyze. Please verify server.js is running.",
      );
    } finally {
      setLoading(false);
    }
  }

  function renderResults(data) {
    const { parsed, features, score, isPhishing, riskLevel, threatReasons } =
      data;

    // 1. Display Target URL
    if (analyzedUrlDisplay) {
      analyzedUrlDisplay.textContent = parsed?.fullUrl || data.url;
    }

    const heuristicScore = score !== undefined ? score : 0;
    // Phishing status & color scheme strictly determined by ML model isPhishing value (1 = Phishing, 0 = Legitimate)
    const isPhishingThreat = isPhishing === 1;

    // 2. Configure UI Theme & Badge Styling
    let badgeClass = "status-safe";
    let iconClass = "fa-shield-check";
    let levelText = "SAFE / LEGITIMATE";
    let fillStroke = "var(--color-safe)"; // Green #10b981

    if (isPhishingThreat) {
      badgeClass = "status-danger";
      iconClass = "fa-skull-crossbones";
      levelText = riskLevel || "PHISHING THREAT";
      fillStroke = "var(--color-danger)"; // Red #ef4444
    } else {
      badgeClass = "status-safe";
      iconClass = "fa-shield-check";
      levelText = riskLevel || "SAFE / LEGITIMATE";
      fillStroke = "var(--color-safe)"; // Green #10b981
    }

    // Apply Styling
    if (riskBadge) riskBadge.className = `risk-badge ${badgeClass}`;
    if (riskIcon) riskIcon.className = `fa-solid ${iconClass}`;
    if (riskLevelText) riskLevelText.textContent = levelText;

    // 3. Render Circular Gauge Score (using score calculated by urlanalyzer)
    if (riskScoreNumber) {
      riskScoreNumber.textContent = heuristicScore;
      riskScoreNumber.style.color = fillStroke;
    }

    if (gaugeFill) {
      const circumference = 264;
      const dashOffset = circumference * (1 - heuristicScore / 100);
      gaugeFill.style.strokeDashoffset = dashOffset;
      gaugeFill.style.stroke = fillStroke;
    }

    // 4. Update Summary Indicators
    if (indProtocol) {
      const targetUrl = parsed?.fullUrl || data.url || "";
      const isHttps = targetUrl.startsWith("https://");
      indProtocol.textContent = isHttps ? "HTTPS Secure" : "HTTP Unencrypted";
      indProtocol.className = isHttps ? "text-safe" : "text-danger";
    }

    if (indDomainType) {
      if (features?.usesIpAddress?.val) {
        indDomainType.textContent = "Raw IP Hostname";
        indDomainType.className = "text-danger";
      } else if (features?.isShortener?.val) {
        indDomainType.textContent = "URL Shortener";
        indDomainType.className = "text-warn";
      } else {
        indDomainType.textContent = "Standard Domain";
        indDomainType.className = isPhishingThreat
          ? "text-danger"
          : "text-safe";
      }
    }

    if (indTriggerCount) {
      if (!isPhishingThreat && heuristicScore < 25) {
        indTriggerCount.textContent = "0 Flags (Clean)";
        indTriggerCount.className = "text-safe";
      } else {
        const warningCount = (threatReasons || []).filter(
          (r) => !r.includes("Passed") && !r.includes("basic lexical"),
        ).length;
        indTriggerCount.textContent = `${Math.max(1, warningCount)} Threat Warnings`;
        indTriggerCount.className =
          isPhishingThreat ? "text-danger" : "text-warn";
      }
    }

    // 5. Render Threat Analysis Findings
    if (reasonsContainer) {
      reasonsContainer.innerHTML = "";

      if (!isPhishingThreat && heuristicScore < 25) {
        // Render Green Safe Finding Card
        reasonsContainer.innerHTML = `
                    <div class="reason-item safe-item" style="border-left: 4px solid var(--color-safe); background: rgba(16, 185, 129, 0.08); padding: 14px; border-radius: 8px; display: flex; align-items: center; gap: 12px;">
                        <i class="fa-solid fa-circle-check reason-icon text-safe" style="color: var(--color-safe); font-size: 1.4rem;"></i>
                        <div class="reason-content">
                            <span class="reason-title" style="color: var(--color-safe); font-weight: 700; font-size: 0.95rem; display: block; margin-bottom: 2px;">Security Validation Passed</span>
                            <span class="reason-desc" style="color: var(--text-secondary); font-size: 0.88rem;">
                                ${threatReasons && threatReasons[0] ? threatReasons[0] : "URL passed security validation tests with no critical threat indicators."}
                            </span>
                        </div>
                    </div>
                `;
      } else {
        // Render Threat Finding Cards
        (threatReasons || []).forEach((reason) => {
          const isDanger =
            isPhishingThreat ||
            reason.includes("IP address") ||
            reason.includes("spoofing");
          const itemDiv = document.createElement("div");
          itemDiv.className = `reason-item ${isDanger ? "danger-item" : "warn-item"}`;
          itemDiv.style.borderLeft = isDanger
            ? "4px solid var(--color-danger)"
            : "4px solid var(--color-warn)";
          itemDiv.style.padding = "14px";
          itemDiv.style.borderRadius = "8px";
          itemDiv.style.display = "flex";
          itemDiv.style.alignItems = "center";
          itemDiv.style.gap = "12px";
          itemDiv.style.marginBottom = "8px";

          itemDiv.innerHTML = `
                        <i class="fa-solid ${isDanger ? "fa-triangle-exclamation" : "fa-circle-exclamation"} reason-icon" style="color: ${isDanger ? "var(--color-danger)" : "var(--color-warn)"}; font-size: 1.3rem;"></i>
                        <div class="reason-content">
                            <span class="reason-title" style="color: ${isDanger ? "var(--color-danger)" : "var(--color-warn)"}; font-weight: 700; font-size: 0.95rem; display: block; margin-bottom: 2px;">${isDanger ? "Threat Vector Identified" : "Security Notice"}</span>
                            <span class="reason-desc" style="color: var(--text-secondary); font-size: 0.88rem;">${reason}</span>
                        </div>
                    `;
          reasonsContainer.appendChild(itemDiv);
        });
      }
    }

    // 6. Reveal Results Card
    if (resultsCard) {
      resultsCard.classList.remove("hidden");
    }
  }
});
