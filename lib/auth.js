/**
 * Authentication Module
 * Handles Salesforce authentication and token management with SSO compatibility
 */
const fs = require("fs");
const express = require("express");
const axios = require("axios");
const { execSync } = require("child_process");
const chalk = require("chalk");
const path = require("path");
const config = require("../config/config");
const utils = require("./utils"); // Import full utils object

/**
 * Performs interactive authentication with Salesforce
 * Checks for cached tokens and initiates web auth flow if needed
 * @returns {Promise<Object>} Authentication tokens
 */
async function interactiveAuth() {
  // Check if we have stored tokens and they're still valid
  if (fs.existsSync(config.TOKEN_FILE)) {
    try {
      const tokens = JSON.parse(fs.readFileSync(config.TOKEN_FILE, "utf8"));
      // Simple validation - check if token isn't expired
      // Salesforce tokens typically last 2 hours
      const issuedAt = new Date(tokens.issued_at || tokens.issued_time || 0);
      const now = new Date();
      const twoHoursInMs = 2 * 60 * 60 * 1000;

      if (now - issuedAt < twoHoursInMs) {
        utils.log("info", "Using cached token - still valid");
        return tokens;
      } else {
        utils.log("info", "Cached token expired - need to re-authenticate");
      }
    } catch (err) {
      utils.log("info", "Cached token invalid - need to re-authenticate");
    }
  }

  utils.log("info", "DataDragon needs to authenticate with Salesforce.");
  utils.log("info", "Starting SSO-compatible web authentication flow...");

  try {
    // For SSO environments, we always use the web server flow
    return await webServerOAuth();
  } catch (error) {
    utils.log("error", `Authentication failed: ${error.message}`);
    throw error;
  }
}

/**
 * Implements OAuth web server flow for Salesforce
 * Handles SSO redirects and token exchange
 * @returns {Promise<Object>} Authentication tokens
 */
async function webServerOAuth() {
  return new Promise((resolve, reject) => {
    utils.log("info", "Starting web server for SSO-compatible OAuth flow...");
    const app = express();
    let server;
    let authTimeout;

    // Root route - Redirect to Salesforce login with SSO parameters
    app.get("/", (req, res) => {
      // Include prompt=login to force SSO each time
      const loginUrl = `${
        config.SF_LOGIN_URL
      }/services/oauth2/authorize?response_type=code&client_id=${
        config.SF_CLIENT_ID
      }&redirect_uri=${encodeURIComponent(
        config.SF_CALLBACK_URL
      )}&prompt=login`;

      utils.log("info", "Redirecting to Salesforce SSO login...");
      res.redirect(loginUrl);
    });

    // OAuth callback - receives auth code, exchanges for tokens
    app.get("/oauth/callback", async (req, res) => {
      if (authTimeout) {
        clearTimeout(authTimeout);
        authTimeout = null;
      }

      const authCode = req.query.code;
      const error = req.query.error;
      const errorDesc = req.query.error_description;

      // Handle error from Salesforce
      if (error) {
        utils.log(
          "error",
          `OAuth error: ${error} - ${errorDesc || "No description"}`
        );
        res.status(400).send(`<html><body>
          <h2>Authentication Error</h2>
          <p>${error}: ${errorDesc || "No description"}</p>
          <p>Please close this window and try again.</p>
        </body></html>`);

        // Close server after a delay to ensure response is sent
        setTimeout(() => {
          server.close();
          reject(
            new Error(
              `OAuth error: ${error} - ${errorDesc || "No description"}`
            )
          );
        }, 2000);
        return;
      }

      if (!authCode) {
        res.status(400).send(`<html><body>
          <h2>Authentication Error</h2>
          <p>Authorization code missing. Please close this window and try again.</p>
        </body></html>`);

        // Close server after a delay to ensure response is sent
        setTimeout(() => {
          server.close();
          reject(new Error("Authorization code missing"));
        }, 2000);
        return;
      }

      try {
        const tokens = await exchangeAuthCodeForToken(authCode);

        // Add issued timestamp
        tokens.issued_at = new Date().toISOString();

        // Use absolute paths from current working directory to ensure reliability
        const outputDir = path.join(process.cwd(), "output");
        const tokenFile = path.join(outputDir, "tokens.json");

        // Create directory if needed
        if (!fs.existsSync(outputDir)) {
          fs.mkdirSync(outputDir, { recursive: true });
        }

        // Write token to file
        fs.writeFileSync(tokenFile, JSON.stringify(tokens, null, 2));

        // Send a nicer HTML response that auto-closes after a few seconds
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

        // Give the browser time to display the success message before closing server
        setTimeout(() => {
          server.close(() => {
            utils.log(
              "info",
              "SSO Authentication successful! Web server stopped."
            );
            resolve(tokens);
          });
        }, 1000);
      } catch (error) {
        utils.log("error", `OAuth token exchange failed: ${error.message}`);

        res.status(500).send(`<html><body>
          <h2>Authentication Error</h2>
          <p>OAuth token exchange failed: ${error.message}</p>
          <p>Please close this window and try again.</p>
        </body></html>`);

        // Close server after a delay to ensure response is sent
        setTimeout(() => {
          server.close(() => reject(error));
        }, 2000);
      }
    });

    // Enhanced error handling for the server
    const serverErrorHandler = (error) => {
      utils.log("error", `Web server error: ${error}`);
      reject(error);
    };

    // Start the server with error handling
    try {
      server = app.listen(3000, () => {
        utils.log(
          "info",
          "Please visit http://localhost:3000 in your browser to authenticate with SSO"
        );

        // Try to open browser automatically
        try {
          const open =
            process.platform === "darwin"
              ? "open"
              : process.platform === "win32"
              ? "start"
              : "xdg-open";
          execSync(`${open} http://localhost:3000`);
        } catch (err) {
          utils.log(
            "warn",
            "Unable to open browser automatically. Please navigate to http://localhost:3000"
          );
        }

        // Set a timeout in case user doesn't complete authentication
        authTimeout = setTimeout(() => {
          utils.log("warn", "Authentication timeout. Please try again.");
          server.close();
          reject(new Error("Authentication timeout"));
        }, 5 * 60 * 1000); // 5 minutes timeout
      });

      server.on("error", serverErrorHandler);
    } catch (error) {
      serverErrorHandler(error);
    }
  });
}

/**
 * Exchanges authorization code for OAuth tokens
 * @param {string} code - Authorization code from OAuth callback
 * @returns {Promise<Object>} Authentication tokens
 */
async function exchangeAuthCodeForToken(code) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: config.SF_CLIENT_ID,
    client_secret: config.SF_CLIENT_SECRET,
    redirect_uri: config.SF_CALLBACK_URL,
  });

  const response = await axios.post(
    `${config.SF_LOGIN_URL}/services/oauth2/token`,
    params.toString()
  );

  return response.data;
}

module.exports = {
  interactiveAuth,
  webServerOAuth,
  exchangeAuthCodeForToken,
};
