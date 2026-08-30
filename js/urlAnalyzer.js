/**
 * PhishShield Web Client — URL Threat Analyzer
 * Communicates with Node.js Express REST API (http://localhost:5000/api/analyze)
 */

document.addEventListener("DOMContentLoaded", function () {
    const API_ENDPOINT = "http://localhost:5000/api/analyze";

    const analyzerForm       = document.getElementById("analyzerForm");
    const urlInput           = document.getElementById("urlInput");
    const clearBtn           = document.getElementById("clearBtn");
    const analyzeBtn         = document.getElementById("analyzeBtn");
    const sampleChips        = document.querySelectorAll(".chip[data-sample]");

    const loadingCard        = document.getElementById("loadingCard");
    const resultsCard        = document.getElementById("resultsCard");
    const errorCard          = document.getElementById("errorCard");
    const errorTitle         = document.getElementById("errorTitle");
    const errorMessage       = document.getElementById("errorMessage");

    const analyzedUrlDisplay = document.getElementById("analyzedUrlDisplay");
    const riskBadge          = document.getElementById("riskBadge");
    const riskIcon           = document.getElementById("riskIcon");
    const riskLevelText      = document.getElementById("riskLevelText");
    const riskScoreNumber    = document.getElementById("riskScoreNumber");
    const gaugeFill          = document.getElementById("gaugeFill");

    const indProtocol        = document.getElementById("indProtocol");
    const indDomainType      = document.getElementById("indDomainType");
    const indTriggerCount    = document.getElementById("indTriggerCount");
    const reasonsContainer   = document.getElementById("reasonsContainer");

    // Show / Hide clear input button
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

    // Sample URL chips click handler
    sampleChips.forEach(chip => {
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

    // Form submit handler
    if (analyzerForm) {
        analyzerForm.addEventListener("submit", function (e) {
            e.preventDefault();
            const val = urlInput ? urlInput.value.trim() : "";
            if (val) {
                runScan(val);
            } else {
                showError("Input Required", "Please enter a valid website URL to analyze.");
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
        if (errorMessage) errorMessage.textContent = msg || "An unexpected error occurred.";
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
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: urlStr })
            });

            const data = await response.json();

            if (!response.ok || !data.valid) {
                const msg = data.error || `HTTP ${response.status}: ${response.statusText}`;
                showError("Validation Error", msg);
                return;
            }

            renderResults(data);
        } catch (err) {
            console.error("API connection error:", err);
            showError(
                "Connection Refused",
                "Cannot connect to PhishShield API backend at http://localhost:5000. Please verify server.js is running."
            );
        } finally {
            setLoading(false);
        }
    }

    function renderResults(data) {
        const { parsed, features, riskLevel, score, threatReasons } = data;

        // Display Analyzed URL
        if (analyzedUrlDisplay) {
            analyzedUrlDisplay.textContent = parsed.fullUrl;
        }

        // Configure Risk Badge & Styling
        const scorePercent = score || 0;
        let badgeClass = "status-safe";
        let iconClass = "fa-shield-check";
        let levelText = "LEGITIMATE";
        let fillStroke = "var(--color-safe)";

        if (scorePercent >= 65) {
            badgeClass = "status-danger";
            iconClass = "fa-skull-crossbones";
            levelText = "PHISHING THREAT";
            fillStroke = "var(--color-danger)";
        } else if (scorePercent >= 25) {
            badgeClass = "status-warn";
            iconClass = "fa-triangle-exclamation";
            levelText = "SUSPICIOUS";
            fillStroke = "var(--color-warn)";
        }

        if (riskBadge) {
            riskBadge.className = `risk-badge ${badgeClass}`;
        }
        if (riskIcon) {
            riskIcon.className = `fa-solid ${iconClass}`;
        }
        if (riskLevelText) {
            riskLevelText.textContent = riskLevel || levelText;
        }

        // Update Circular Gauge (circumference = 2 * π * 42 ≈ 263.89)
        if (riskScoreNumber) {
            riskScoreNumber.textContent = scorePercent;
            riskScoreNumber.style.color = fillStroke;
        }
        if (gaugeFill) {
            const circumference = 264;
            const dashOffset = circumference * (1 - scorePercent / 100);
            gaugeFill.style.strokeDashoffset = dashOffset;
            gaugeFill.style.stroke = fillStroke;
        }

        // Key Summary Indicators
        if (indProtocol) {
            if (features.isHttps.val) {
                indProtocol.textContent = "HTTPS Secure";
                indProtocol.className = "text-safe";
            } else {
                indProtocol.textContent = "HTTP Unencrypted";
                indProtocol.className = "text-danger";
            }
        }

        if (indDomainType) {
            if (features.usesIpAddress.val) {
                indDomainType.textContent = "Raw IP Hostname";
                indDomainType.className = "text-danger";
            } else if (features.isShortener.val) {
                indDomainType.textContent = "URL Shortener";
                indDomainType.className = "text-warn";
            } else if (data.isKnownLegit) {
                indDomainType.textContent = "Verified Established";
                indDomainType.className = "text-safe";
            } else {
                indDomainType.textContent = "Standard Web Host";
                indDomainType.className = "";
            }
        }

        if (indTriggerCount) {
            const warningCount = (threatReasons || []).filter(
                r => !r.includes("No explicit threat") && !r.includes("appears structurally safe")
            ).length;

            if (warningCount === 0) {
                indTriggerCount.textContent = "0 Flags (Clean)";
                indTriggerCount.className = "text-safe";
            } else if (warningCount >= 3) {
                indTriggerCount.textContent = `${warningCount} Threat Warnings`;
                indTriggerCount.className = "text-danger";
            } else {
                indTriggerCount.textContent = `${warningCount} Warnings`;
                indTriggerCount.className = "text-warn";
            }
        }

        // Render Threat Findings List
        if (reasonsContainer) {
            reasonsContainer.innerHTML = "";

            (threatReasons || []).forEach(reason => {
                const isClean = reason.includes("appears structurally safe") || reason.includes("No explicit threat");
                const itemDiv = document.createElement("div");

                if (isClean) {
                    itemDiv.className = "reason-item safe-item";
                    itemDiv.innerHTML = `
                        <i class="fa-solid fa-circle-check reason-icon"></i>
                        <div class="reason-content">
                            <span class="reason-title">Structural Validation Passed</span>
                            <span class="reason-desc">${reason}</span>
                        </div>
                    `;
                } else {
                    const isHighRisk = scorePercent >= 65 || reason.includes("IP address") || reason.includes("Deceptive") || reason.includes("spoofing");
                    itemDiv.className = `reason-item ${isHighRisk ? 'danger-item' : 'warn-item'}`;
                    itemDiv.innerHTML = `
                        <i class="fa-solid ${isHighRisk ? 'fa-triangle-exclamation' : 'fa-circle-exclamation'} reason-icon"></i>
                        <div class="reason-content">
                            <span class="reason-title">Risk Factor Identified</span>
                            <span class="reason-desc">${reason}</span>
                        </div>
                    `;
                }

                reasonsContainer.appendChild(itemDiv);
            });
        }

        // Reveal Results Dashboard
        if (resultsCard) {
            resultsCard.classList.remove("hidden");
        }
    }
});
