/**
 * Utility Module
 * Common utility functions for the DataDragon application
 */
const chalk = require("chalk");
const boxen = require("boxen");

/**
 * Displays the application banner with styling
 */
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

/**
 * Enhances severity level based on a multiplier
 * @param {string} baseSeverity - Base severity level (low, medium, high, critical)
 * @param {number} multiplier - Severity multiplier
 * @returns {string} Enhanced severity level
 */
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

/**
 * Logs messages with consistent formatting and colors
 * @param {string} level - Log level (debug, info, warn, error, risk)
 * @param {string} message - Message to log
 * @returns {Function} Chalk color function for the log level
 */
function log(level, message) {
  const logLevels = {
    debug: { display: false, color: chalk.gray, prefix: "[DEBUG]" },
    info: { display: true, color: chalk.white, prefix: "[INFO]" },
    warn: { display: true, color: chalk.yellow, prefix: "[WARN]" },
    error: { display: true, color: chalk.red, prefix: "[ERROR]" },
    risk: { display: true, color: null, prefix: "" }, // Color will be determined by severity
  };

  // Parse config from environment
  const envLogLevel = (process.env.LOG_LEVEL || "info").toLowerCase();

  // Only display logs at or above configured level, always hide debug unless explicitly set
  const shouldDisplay = 
    (level !== 'debug' || envLogLevel === 'debug') && (
      logLevels[level]?.display || 
      level === envLogLevel
    );

  if (shouldDisplay) {
    const prefix = logLevels[level]?.prefix || `[${level.toUpperCase()}]`;
    let colorFn = logLevels[level]?.color || chalk.white;
    
    if (level === 'risk') {
      // Extract severity from message for proper coloring
      let severity = "low";
      
      // Determine severity level from message
      if (message.toLowerCase().startsWith('critical')) {
        severity = "critical";
      } else if (message.toLowerCase().startsWith('high')) {
        severity = "high";
      } else if (message.toLowerCase().startsWith('medium')) {
        severity = "medium";
      }
      
      // Format message with appropriate indicator and color
      const indicator = getSeverityIndicator(severity);
      let formattedMessage = message;
      
      // If message already starts with severity as text, replace it with the indicator
      if (message.toLowerCase().startsWith(severity)) {
        formattedMessage = `${indicator} ${message.substring(severity.length).trim()}`;
      }
      
      // Apply colors based on severity
      switch (severity) {
        case "critical":
          console.log(chalk.red.bold(formattedMessage));
          break;
        case "high":
          console.log(chalk.hex('#FF8C00').bold(formattedMessage));
          break;
        case "medium":
          console.log(chalk.yellow(formattedMessage));
          break;
        default:
          console.log(chalk.blue(formattedMessage));
          break;
      }
    } else {
      console.log(colorFn(`${prefix} ${message}`));
    }
  }

  return logLevels[level]?.color || chalk.white;
}

/**
 * Calculates overall risk level based on risk profile
 * @param {Object} riskProfile - Risk profile with counts by severity
 * @returns {string} Overall risk level
 */
function calculateOverallRiskLevel(riskProfile) {
  if (riskProfile.critical > 0) return "critical";
  if (riskProfile.high > 2) return "high";
  if (riskProfile.high > 0 || riskProfile.medium > 5) return "medium";
  return "low";
}

/**
 * Gets appropriate chalk color function for risk level
 * @param {string} riskLevel - Risk level (critical, high, medium, low)
 * @returns {Function} Chalk color function
 */
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

/**
 * Gets text indicator for severity level
 * @param {string} severity - Severity level
 * @returns {string} Text indicator for severity
 */
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
    // Add standardized mappings for fields that commonly cause "unknown" issues
    endpointUrl: getStandardizedField(
      row,
      ["URL", "ENDPOINT_URL", "URI"],
      null
    ),
    componentName: getStandardizedField(
      row,
      ["COMPONENT_TYPE", "COMPONENT_NAME", "COMPONENT"],
      null
    ),
    linkedEntityId: getStandardizedField(
      row, 
      ["LINKED_ENTITY_ID", "RELATED_RECORD_ID", "ENTITY_ID"],
      null
    ),
    sharedWithEntity: getStandardizedField(
      row,
      ["SHARED_WITH_ENTITY_ID", "LINKED_ENTITY_ID", "RELATED_RECORD_ID", "ENTITY_ID"],
      null
    ),
    sharedWithName: getStandardizedField(
      row,
      ["SHARED_WITH_ENTITY_NAME", "ENTITY_NAME", "SHARED_WITH_NAME"],
      null
    ),
    documentId: getStandardizedField(
      row,
      ["DOCUMENT_ID", "CONTENT_ID", "CONTENT_DOCUMENT_ID"],
      null
    ),
    dashboardId: getStandardizedField(
      row,
      ["DASHBOARD_ID", "DASHBOARD_NAME"],
      null
    ),
    action: getStandardizedField(
      row,
      ["ACTION", "METHOD", "OPERATION_TYPE", "OPERATION"],
      null
    )
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
