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

// Handle a reusable way to log at different levels - no emojis
function log(level, message, ...args) {
  const logLevel = process.env.LOG_LEVEL || "info";
  const levels = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  if (levels[level] >= levels[logLevel]) {
    let logFn = console.log;
    let prefix = "";

    switch (level) {
      case "debug":
        prefix = chalk.gray("[DEBUG]");
        break;
      case "info":
        prefix = chalk.cyan("[INFO]");
        break;
      case "warn":
        prefix = chalk.yellow("[WARN]");
        break;
      case "error":
        prefix = chalk.red("[ERROR]");
        break;
    }

    logFn(`${prefix} ${message}`, ...args);
  }
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

module.exports = {
  displayBanner,
  enhanceSeverity,
  log,
  calculateOverallRiskLevel,
  getRiskColor,
  getSeverityIndicator,
};
