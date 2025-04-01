// Utility functions for DataDragon
const chalk = require("chalk");
const boxen = require("boxen");

// Display themed banner
function displayBanner() {
  console.log(
    chalk.greenBright(
      boxen(
        "DataDragon: Guardian of the Salesforce Hoard\n" +
          "        Watching Over Your Data Treasures",
        { padding: 1, borderStyle: "round", borderColor: "yellow" }
      )
    )
  );
}

// Function to enhance severity based on a multiplier
function enhanceSeverity(baseSeverity, multiplier) {
  const severityLevels = ["low", "medium", "high", "critical"];
  const currentIndex = severityLevels.indexOf(baseSeverity);

  if (currentIndex === -1) return baseSeverity; // Unknown severity

  // Calculate new index based on multiplier
  // Multiplier of 2 moves up one level, 3 moves up two levels, etc.
  const levelIncrease = Math.min(
    Math.floor(multiplier) - 1,
    severityLevels.length - 1 - currentIndex
  );
  const newIndex = Math.min(
    currentIndex + levelIncrease,
    severityLevels.length - 1
  );

  return severityLevels[newIndex];
}

// Consistent logging with colors and formatting
function log(level, message) {
  const logLevels = {
    debug: { display: false, color: chalk.gray, prefix: "[DEBUG]" },
    info: { display: true, color: chalk.cyan, prefix: "[INFO]" },
    warn: { display: true, color: chalk.yellow, prefix: "[WARN]" },
    error: { display: true, color: chalk.red, prefix: "[ERROR]" },
    risk: { display: true, color: chalk.red.bold, prefix: "" },
  };

  // Parse config from environment
  const envLogLevel = (process.env.LOG_LEVEL || "info").toLowerCase();

  // Only display logs at or above configured level
  const shouldDisplay =
    logLevels[level]?.display || level === envLogLevel || envLogLevel === "debug";

  if (shouldDisplay) {
    const prefix = logLevels[level]?.prefix || `[${level.toUpperCase()}]`;
    const colorFn = logLevels[level]?.color || chalk.white;
    
    if (level === 'risk') {
      // Risk messages already include their prefix
      console.log(colorFn(message));
    } else {
      console.log(colorFn(`${prefix} ${message}`));
    }
  }

  return logLevels[level]?.color || chalk.white;
}

// Helper function to calculate overall risk level
function calculateOverallRiskLevel(riskProfile) {
  if (riskProfile.critical > 0) return "critical";
  if (riskProfile.high > 2) return "high";
  if (riskProfile.high > 0 || riskProfile.medium > 5) return "medium";
  return "low";
}

// Helper function to get appropriate color for risk level
function getRiskColor(riskLevel) {
  switch (riskLevel) {
    case "critical":
      return chalk.bgRed.white;
    case "high":
      return chalk.red;
    case "medium":
      return chalk.yellow;
    default:
      return chalk.blue;
  }
}

// Helper function to get severity indicator for text files
function getSeverityIndicator(severity) {
  switch (severity) {
    case "critical":
      return "[CRITICAL]";
    case "high":
      return "[HIGH]";
    case "medium":
      return "[MEDIUM]";
    default:
      return "[LOW]";
  }
}

/**
 * Get standardized field value from log row with fallbacks for different field names
 * @param {Object} row - Log data row
 * @param {string[]} fieldNames - Possible field names in priority order
 * @param {*} defaultValue - Default value if no fields are found
 * @returns {*} Field value or default
 */
function getStandardizedField(row, fieldNames, defaultValue = null) {
  if (!row) return defaultValue;

  for (const field of fieldNames) {
    if (row[field] !== undefined && row[field] !== null && row[field] !== "") {
      return row[field];
    }
  }

  return defaultValue;
}

/**
 * Extract date part from timestamp string (YYYY-MM-DD)
 * @param {string} timestamp - Timestamp string in ISO format
 * @returns {string|null} Date part or null if invalid
 */
function extractDateFromTimestamp(timestamp) {
  if (!timestamp || typeof timestamp !== "string") return null;

  // Try to extract the date part from an ISO timestamp (2025-03-10T19:00:09.648Z)
  const match = timestamp.match(/^(\d{4}-\d{2}-\d{2})/);
  return match ? match[1] : null;
}

/**
 * Get standard fields using consistent naming across different event log types
 * @param {Object} row - Log data row
 * @returns {Object} Object with standardized field names
 */
function getStandardFields(row) {
  if (!row) return {};

  // First, get the timestamp which we'll use for date extraction
  const timestamp = getStandardizedField(
    row,
    [
      "TIMESTAMP_DERIVED",
      "EVENT_TIME",
      "TIMESTAMP",
      "LOGIN_TIME",
      "CREATED_DATE",
    ],
    null
  );

  // Extract date from timestamp or use fallbacks
  let date = null;
  if (timestamp) {
    date = extractDateFromTimestamp(timestamp);
  }

  // If we couldn't extract date from timestamp, look for direct date fields
  if (!date) {
    date = getStandardizedField(
      row,
      ["EVENT_DATE", "LOG_DATE"],
      new Date().toISOString().split("T")[0]
    );
  }

  return {
    userId: getStandardizedField(row, ["USER_ID_DERIVED"], "unknown"),
    username: getStandardizedField(row, ["USERNAME", "USER_NAME"], null),
    date: date,
    timestamp: timestamp,
    sessionKey: getStandardizedField(
      row,
      ["SESSION_KEY", "SESSION_ID", "SESSIONKEY", "SESSION_IDENTIFIER"],
      "unknown-session"
    ),
    clientIp: getStandardizedField(
      row,
      ["CLIENT_IP", "SOURCE_IP", "IP_ADDRESS", "SOURCEIP"],
      "unknown"
    ),
    eventType: getStandardizedField(
      row,
      ["EVENT_TYPE", "EVENTTYPE"],
      "Unknown"
    ),
  };
}

module.exports = {
  displayBanner,
  enhanceSeverity,
  log,
  calculateOverallRiskLevel,
  getRiskColor,
  getSeverityIndicator,
  getStandardizedField,
  getStandardFields,
  extractDateFromTimestamp,
};
