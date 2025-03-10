// Configuration setup
const path = require("path");
const fs = require("fs");

// Environment variables from .env file
const {
  SF_LOGIN_URL,
  SF_CLIENT_ID,
  SF_CLIENT_SECRET,
  SF_CALLBACK_URL,
  TARGET_USERS,
  USERS_CSV = "target-users.csv", // Default users CSV file
  LOG_LEVEL = "info",
  SCAN_LIMIT = null,
} = process.env;

// Global constants - using absolute paths for better reliability
const OUTPUT_DIR = path.join(__dirname, "../output");
const TOKEN_FILE = path.join(OUTPUT_DIR, "tokens.json");
const EVENT_LOG_DIR = path.join(OUTPUT_DIR, "eventLogs");
const SUMMARY_JSON = path.join(OUTPUT_DIR, "summary-report.json");
const SUMMARY_CSV = path.join(OUTPUT_DIR, "summary-report.csv");

// Create necessary directories if they don't exist
const ensureDirectoriesExist = () => {
  const directories = [OUTPUT_DIR, EVENT_LOG_DIR];

  directories.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });

        console.log(`Created directory: ${dir}`);
      } catch (error) {
        console.error(`Error creating directory ${dir}: ${error.message}`);
      }
    }
  });
};

// Validate essential configuration
const validate = () => {
  const requiredVars = [
    "SF_LOGIN_URL",
    "SF_CLIENT_ID",
    "SF_CLIENT_SECRET",
    "SF_CALLBACK_URL",
  ];
  const missing = requiredVars.filter((varName) => !module.exports[varName]);

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`
    );
  }

  if (!TARGET_USERS && !USERS_CSV) {
    throw new Error("Either TARGET_USERS or USERS_CSV must be specified");
  }

  return true;
};

// Export configuration
module.exports = {
  // Salesforce connection settings
  SF_LOGIN_URL,
  SF_CLIENT_ID,
  SF_CLIENT_SECRET,
  SF_CALLBACK_URL,

  // User configuration
  TARGET_USERS,
  USERS_CSV,

  // Output paths
  OUTPUT_DIR,
  TOKEN_FILE,
  EVENT_LOG_DIR,
  SUMMARY_JSON,
  SUMMARY_CSV,

  // Processing configuration
  LOG_LEVEL,
  SCAN_LIMIT: SCAN_LIMIT ? parseInt(SCAN_LIMIT, 10) : null,
  BATCH_SIZE: 5, // Process 5 logs at a time

  // Utility functions
  ensureDirectoriesExist,
  validate,
};
