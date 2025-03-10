// Authentication routes
const express = require("express");
const router = express.Router();
const config = require("../config/config");
const { exchangeAuthCodeForToken } = require("../lib/auth");
const { log } = require("../lib/utils");
const fs = require("fs");

// Root route - Automatically redirect to Salesforce login page
router.get("/", (req, res) => {
  const loginUrl = `${
    config.SF_LOGIN_URL
  }/services/oauth2/authorize?response_type=code&client_id=${
    config.SF_CLIENT_ID
  }&redirect_uri=${encodeURIComponent(config.SF_CALLBACK_URL)}&prompt=login`;
  res.redirect(loginUrl);
});

// OAuth callback - receives auth code, exchanges for tokens
router.get("/oauth/callback", async (req, res) => {
  const authCode = req.query.code;
  const error = req.query.error;
  const errorDesc = req.query.error_description;

  // Handle error from Salesforce
  if (error) {
    log("error", `OAuth error: ${error} - ${errorDesc || "No description"}`);

    return res.status(400).send(`<html><body>
      <h2>Authentication Error</h2>
      <p>${error}: ${errorDesc || "No description"}</p>
      <p>Please close this window and try again.</p>
    </body></html>`);
  }

  if (!authCode) {
    return res.status(400).send(`<html><body>
      <h2>Authentication Error</h2>
      <p>Authorization code missing. Please close this window and try again.</p>
    </body></html>`);
  }

  try {
    const tokens = await exchangeAuthCodeForToken(authCode);

    // Add issued timestamp
    tokens.issued_at = new Date().toISOString();

    // Create directory if it doesn't exist
    const tokenDir = config.TOKEN_FILE.substring(
      0,
      config.TOKEN_FILE.lastIndexOf("/")
    );
    if (!fs.existsSync(tokenDir)) {
      fs.mkdirSync(tokenDir, { recursive: true });
    }

    fs.writeFileSync(config.TOKEN_FILE, JSON.stringify(tokens, null, 2));

    // Send success HTML with auto-close
    res.send(`<html><body>
      <h2>DataDragon Authentication Successful!</h2>
      <p>You have successfully authenticated with Salesforce.</p>
      <p>You can now close this window. DataDragon is continuing to process logs...</p>
      <script>
        // Auto-close the window after 3 seconds
        setTimeout(function() {
          window.close();
        }, 3000);
      </script>
      <style>
        body {
          font-family: Arial, sans-serif;
          margin: 40px;
          text-align: center;
          color: #333;
        }
        h2 {
          color: #006400;
        }
      </style>
    </body></html>`);

    // Emit the 'authorized' event so main app can continue
    req.app.emit("authorized", tokens);
  } catch (error) {
    log("error", `OAuth token exchange failed: ${error.message}`);

    res.status(500).send(`<html><body>
      <h2>Authentication Error</h2>
      <p>OAuth token exchange failed: ${error.message}</p>
      <p>Please close this window and try again.</p>
    </body></html>`);
  }
});

module.exports = router;
