/**
 * Phishing Website Detection System — Express API Server
 */
const express = require('express');
const cors = require('cors');
const path = require('path');
const { extractFeatures } = require('./utils/featureExtractor');
const { evaluateThreat } = require('./utils/threatEvaluator');

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS middleware for frontend communication
app.use(cors());

// Enable JSON body parsing middleware
app.use(express.json());

// Serve static frontend files (index.html, css, js)
app.use(express.static(path.join(__dirname)));

/**
 * POST /api/analyze
 * Body: { "url": "https://..." }
 * Accepts a URL, performs feature extraction & threat scoring, returns analysis JSON
 */
app.post('/api/analyze', (req, res) => {
    const { url } = req.body || {};

    if (!url || typeof url !== 'string' || !url.trim()) {
        return res.status(400).json({
            valid: false,
            error: "URL is required. Please provide a non-empty string URL."
        });
    }

    try {
        const featureResult = extractFeatures(url);

        if (!featureResult.valid) {
            return res.status(400).json({
                valid: false,
                error: featureResult.error || "Invalid URL syntax."
            });
        }

        const evaluation = evaluateThreat(featureResult);

        return res.json(evaluation);
    } catch (err) {
        console.error("Error analyzing URL:", err);
        return res.status(500).json({
            valid: false,
            error: "An internal server error occurred while analyzing the URL."
        });
    }
});

// Start Express Server
app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  PhishGuard API Server running on port ${PORT}`);
    console.log(`🔗  Analyze Endpoint: http://localhost:${PORT}/api/analyze`);
    console.log(`====================================================`);
});
