/**
 * Phishing Website Detection System — Express API Server
 */
const express = require("express");
const cors = require("cors");
const path = require("path");
const { execFile } = require("child_process");

const { extractFeatures } = require("./utils/featureExtractor");
const { evaluateThreat } = require("./utils/threatEvaluator");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

/**
 * POST /api/analyze
 */
app.post("/api/analyze", (req, res) => {
  const { url } = req.body || {};

  if (!url || typeof url !== "string" || !url.trim()) {
    return res.status(400).json({
      valid: false,
      error: "URL is required. Please enter a valid URL string.",
    });
  }

  // 1. Run Rule-Based Heuristic Evaluation
  let heuristicResult = {
    valid: false,
    score: 0,
    threatReasons: [],
    features: {},
  };
  try {
    const featureData = extractFeatures(url);
    if (featureData.valid) {
      heuristicResult = evaluateThreat(featureData);
    }
  } catch (err) {
    console.error("Heuristic Evaluation Error:", err);
  }

  // 2. Call Python ML Prediction Script
  const pythonCmd = process.platform === "win32" ? "python" : "python3";
  const predictScript = path.join(__dirname, "ml", "predict.py");

  execFile(pythonCmd, [predictScript, url], (error, stdout, stderr) => {
    let isPhishingML = 0;
    let mlScore = heuristicResult.score;

    if (!error && stdout) {
      try {
        const mlResult = JSON.parse(stdout);
        isPhishingML = mlResult.isPhishing;
        mlScore =
          mlResult.phishingRiskScore !== undefined
            ? mlResult.phishingRiskScore
            : heuristicResult.score;
      } catch (pErr) {
        console.error("Failed to parse ML JSON output:", pErr);
      }
    } else {
      console.error(
        "ML Execution Error / Fallback to Rules:",
        stderr || error?.message,
      );
    }

    // Final Verdict: Phishing strictly based on ML isPhishing model output
    const finalIsPhishing = isPhishingML === 1;
    const finalRiskLevel = finalIsPhishing
      ? "PHISHING THREAT"
      : heuristicResult.score >= 40
        ? "SUSPICIOUS"
        : "SAFE / LEGITIMATE";

    return res.json({
      valid: true,
      parsed: { fullUrl: url },
      score: heuristicResult.score, // Rule-based score calculated by urlanalyzer (threatEvaluator.js)
      mlScore: mlScore, // ML probability score
      isPhishing: finalIsPhishing ? 1 : 0, // ML isPhishing binary value (1 = Phishing, 0 = Legitimate)
      riskLevel: finalRiskLevel,
      features: heuristicResult.features || {},
      threatReasons: heuristicResult.threatReasons,
    });
  });
});

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️  PhishShield Express Server running on port ${PORT}`);
  console.log(`🔗  Analyze Endpoint: http://localhost:${PORT}/`);
  console.log(`====================================================`);
});
