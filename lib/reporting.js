/**
 * Data Dragon Reporting Module
 * Handles generation of security analysis reports in various formats
 */
const fs = require("fs");
const path = require("path");
const chalk = require("chalk");
const boxen = require("boxen");
const config = require("../config/config");
const { riskConfig, sanitizeConfigForOutput } = require("../config/riskConfig");
const utils = require("./utils");

// Try loading HTML report generator - gracefully handle if not available
let htmlReportGenerator;
try {
  htmlReportGenerator = require('./reporting/html/generator');
} catch (error) {
  // HTML reporting dependencies might not be installed
  htmlReportGenerator = null;
}

/**
 * Generate final summary report with enhanced user activity data
 * @param {Object} userMap - Map of user IDs to usernames
 * @param {Array} allScannedFiles - List of all scanned log files
 * @param {Array} allWarnings - List of all detected warnings
 * @param {Map} userActivities - Map of user IDs to UserActivity objects
 * @param {Object} riskCorrelations - Risk correlation analysis results
 * @returns {Object} Summary object containing all report data
 */
function generateSummary(
  userMap,
  allScannedFiles,
  allWarnings,
  userActivities,
  riskCorrelations = null
) {
  utils.log(
    "info",
    "Generating detailed summary reports with enhanced user activity data..."
  );

  try {
    // Enhanced summary with user-specific data
    const userSummary = {};

    // Validate userActivities is a Map before using forEach
    if (userActivities && typeof userActivities.forEach === 'function') {
      // Process each user - whether they have warnings or not
      userActivities.forEach((activity, userId) => {
        if (!activity) return;
        
        const username = userMap[userId] || activity.username;

        // Get user's activity summary
        const activitySummary = activity.getSummary();
        if (!activitySummary) return;

        // Get correlation data if available
        const correlationData = riskCorrelations
          ? riskCorrelations.getUserCorrelations(userId)
          : null;

        // Create user summary entry
        userSummary[username] = {
          userId,
          warningCount: activitySummary.warningsCount.total,
          riskProfile: {
            critical: activitySummary.warningsCount.critical,
            high: activitySummary.warningsCount.high,
            medium: activitySummary.warningsCount.medium,
            low: activitySummary.warningsCount.low,
          },
          loginActivity: activitySummary.loginStats,
          anomalies: activitySummary.anomalies,
          riskScore: activitySummary.riskScore,
          riskLevel: activitySummary.riskLevel,
          criticalEvents: activitySummary.criticalEvents || 0,
          highRiskEvents: activitySummary.highRiskEvents || 0,
          riskFactors: activitySummary.riskFactors || [],
          scannedLogs: activitySummary.scannedLogs,
          correlations: correlationData ? correlationData.correlations : [],
          correlationScore: correlationData
            ? correlationData.correlationScore
            : 0,
          warnings: allWarnings
            .filter((w) => w.userId === userId)
            .map((w) => ({
              date: w.date,
              timestamp: w.timestamp,
              warning: formatWarningMessage(w.warning),
              severity: w.severity || "low",
              eventType: w.eventType,
              context: w.context || {},
            })),
        };
      });
    } else {
      utils.log(
        "warn",
        "No valid user activities data available. Generating minimal report."
      );
      
      // Create minimal user summary if userActivities isn't available
      if (userMap) {
        Object.entries(userMap).forEach(([userId, username]) => {
          userSummary[username] = {
            userId,
            warningCount: 0,
            riskProfile: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
            },
            loginActivity: {
              totalDays: 0,
              firstLogin: "N/A",
              lastLogin: "N/A",
            },
            anomalies: [],
            riskScore: 0,
            riskLevel: "none",
            criticalEvents: 0,
            highRiskEvents: 0,
            riskFactors: [],
            scannedLogs: [],
            correlations: [],
            correlationScore: 0,
            warnings: allWarnings
              .filter((w) => w.userId === userId)
              .map((w) => ({
                date: w.date,
                timestamp: w.timestamp,
                warning: formatWarningMessage(w.warning),
                severity: w.severity || "low",
                eventType: w.eventType,
                context: w.context || {},
              })),
          };
        });
      }
    }

    // Event type breakdown
    const eventTypeCounts = {};
    allScannedFiles.forEach(({ EventType }) => {
      eventTypeCounts[EventType] = (eventTypeCounts[EventType] || 0) + 1;
    });

    // Create warnings by event type
    const warningsByEventType = {};
    allWarnings.forEach((warning) => {
      const eventType = warning.eventType || "Unknown";
      warningsByEventType[eventType] = warningsByEventType[eventType] || [];
      warningsByEventType[eventType].push(warning);
    });

    // Get high-risk users if correlations available
    const highRiskUsers = riskCorrelations
      ? riskCorrelations.getHighRiskUsers(10).map((corr) => corr.username)
      : [];

    // Create complete summary object
    const summary = {
      generatedAt: new Date().toISOString(),
      stats: {
        totalUsers: Object.keys(userMap).length,
        totalFiles: allScannedFiles.length,
        totalWarnings: allWarnings.length,
        severeWarnings: allWarnings.filter(
          (w) => w.severity === "critical" || w.severity === "high"
        ).length,
        eventTypesScanned: Object.keys(eventTypeCounts).length,
        highRiskUsers: highRiskUsers.length,
      },
      highRiskUsers,
      scannedFiles: allScannedFiles,
      eventTypeCounts,
      warningsByEventType,
      userSummary,
      monitoredUsers: Object.values(userMap),
      riskConfig: sanitizeConfigForOutput(riskConfig),
    };

    // Ensure output directory exists
    const jsonDir = path.dirname(config.SUMMARY_JSON);
    if (!fs.existsSync(jsonDir)) {
      try {
        fs.mkdirSync(jsonDir, { recursive: true });
        utils.log("info", `Created JSON output directory: ${jsonDir}`);
      } catch (error) {
        throw new Error(`Failed to create JSON output directory: ${error.message}`);
      }
    }

    // Write detailed JSON summary
    fs.writeFileSync(config.SUMMARY_JSON, JSON.stringify(summary, null, 2));

    // Generate CSV summary report
    generateCSV(summary, userMap, allWarnings, userActivities);

    // Generate a visual banner
    generateSummaryBanner(summary);

    // Print user-specific summary to console
    Object.entries(userSummary).forEach(([username, data]) => {
      const riskLevel =
        data.riskLevel || utils.calculateOverallRiskLevel(data.riskProfile);
      const riskColor = utils.getRiskColor(riskLevel);

      utils.log("info", riskColor(`   Risk Level: ${riskLevel.toUpperCase()}`));
      utils.log(
        "info",
        `   Warnings: ${data.warningCount} (Critical: ${data.riskProfile.critical}, High: ${data.riskProfile.high}, Medium: ${data.riskProfile.medium}, Low: ${data.riskProfile.low})`
      );

      utils.log(
        "info",
        `   Login Activity: ${data.loginActivity.totalDays} days (${data.loginActivity.firstLogin} to ${data.loginActivity.lastLogin})`
      );

      if (data.criticalEvents > 0) {
        utils.log(
          "info",
          chalk.red(`   Critical Events: ${data.criticalEvents}`)
        );
      }

      if (data.highRiskEvents > 0) {
        utils.log(
          "info",
          chalk.yellow(`   High Risk Events: ${data.highRiskEvents}`)
        );
      }

      if (data.anomalies && data.anomalies.length > 0) {
        utils.log(
          "info",
          chalk.yellow(`   Anomalies Detected: ${data.anomalies.length}`)
        );
      }

      if (data.riskFactors && data.riskFactors.length > 0) {
        utils.log(
          "info",
          chalk.magenta(`   Risk Factors: ${data.riskFactors.length}`)
        );
      }

      if (data.correlationScore > 0) {
        utils.log(
          "info",
          chalk.yellow(
            `   Correlation Score: ${data.correlationScore.toFixed(1)}`
          )
        );
      }
    });
    
    // Return summary for further processing
    return summary;
  } catch (error) {
    utils.log("error", `Error generating summary: ${error.message}`);
    console.error(error);
    
    // Return a minimal summary in case of error
    return {
      generatedAt: new Date().toISOString(),
      stats: {
        totalUsers: Object.keys(userMap).length,
        totalFiles: allScannedFiles.length,
        totalWarnings: allWarnings.length,
        severeWarnings: allWarnings.filter(
          (w) => w.severity === "critical" || w.severity === "high"
        ).length
      }
    };
  }
}

/**
 * Formats a warning message by removing excess whitespace
 * @param {string} message - Warning message to format
 * @returns {string} Formatted message
 */
function formatWarningMessage(message) {
  if (!message) return "Unknown warning";
  return message.replace(/\s+/g, " ").trim();
}

/**
 * Generate enhanced CSV summary report
 * @param {Object} summary - Complete summary object
 * @param {Object} userMap - Map of user IDs to usernames
 * @param {Array} allWarnings - List of all detected warnings
 * @param {Map} userActivities - Map of user IDs to UserActivity objects
 */
function generateCSV(summary, userMap, allWarnings, userActivities) {
  try {
    // Get all possible context keys across all warnings
    const allContextKeys = new Set();
    allWarnings.forEach((warning) => {
      if (warning.context) {
        Object.keys(warning.context).forEach((key) => allContextKeys.add(key));
      }
    });

    const contextKeysArray = Array.from(allContextKeys);

    // Create headers with enhanced fields including risk factors explanation and event counts
    const basicHeaders = [
      "User",
      "UserId",
      "Date",
      "Time",
      "Warning",
      "Severity",
      "EventType",
      "ClientIP",
      "SessionKey",
      "FirstLoginDate",
      "LastLoginDate",
      "LoginDaysCount",
      "ScannedLogsCount",
      "UniqueIPCount",
      "RiskScore",
      "RiskLevel",
      "CriticalEvents",
      "HighRiskEvents",
      "AnomalyCount",
      "RiskFactorsExplanation", // Detailed risk explanation
    ];

    const headers = [...basicHeaders, ...contextKeysArray];

    const csvHeader = headers.map((h) => `"${h}"`).join(",") + "\n";

    let csvRows = [];

    // Process all users through their UserActivity objects
    if (userActivities && typeof userActivities.forEach === 'function') {
      userActivities.forEach((activity, userId) => {
        if (!activity || typeof activity.getCSVData !== 'function') return;
        
        // Get CSV data rows for this user
        const activityRows = activity.getCSVData();
        
        if (Array.isArray(activityRows)) {
          // Prioritize location change warnings at the beginning
          const priorityRows = activityRows.filter(row => row.priority === true || row.eventType === 'LocationChange');
          const normalRows = activityRows.filter(row => row.priority !== true && row.eventType !== 'LocationChange');
          
          // Add priority rows first, then normal rows
          if (priorityRows.length > 0) {
            csvRows = csvRows.concat(priorityRows);
          }
          
          // Add the rest of the rows
          if (normalRows.length > 0) {
            csvRows = csvRows.concat(normalRows);
          }
        }
      });
    }

    // Handle case where no user activity data is available
    if (csvRows.length === 0 && Object.keys(userMap).length > 0) {
      Object.entries(userMap).forEach(([userId, username]) => {
        const row = {
          username,
          userId,
          date: "N/A",
          time: "N/A",
          warning: "No security risks detected",
          severity: "none",
          eventType: "N/A",
          clientIp: "N/A",
          sessionKey: "N/A",
          firstLoginDate: "N/A",
          lastLoginDate: "N/A",
          loginDaysCount: 0,
          scannedLogsCount: 0,
          uniqueIPs: 0,
          riskScore: 0,
          riskLevel: "none",
          criticalEvents: 0,
          highRiskEvents: 0,
          anomalyCount: 0,
          riskFactorsExplanation: "No risk factors detected",
          context: {},
        };

        csvRows.push(row);
      });
    }

    // Format each row for CSV output
    const formattedRows = csvRows
      .map((row) => {
        // Basic fields - matching the order of basicHeaders
        const basicFields = [
          row.username || "",
          row.userId || "",
          row.date || "N/A",
          row.timestamp || "N/A", // Use timestamp instead of time
          row.warning ? formatWarningMessage(row.warning) : "No security risks detected",
          row.severity || "none",
          row.eventType || "N/A",
          row.clientIp || "N/A",
          row.sessionKey || "N/A",
          row.firstLoginDate || "N/A",
          row.lastLoginDate || "N/A",
          row.loginDaysCount || 0,
          row.scannedLogsCount || 0,
          row.uniqueIPs || 0,
          row.riskScore || 0,
          row.riskLevel || "none",
          row.criticalEvents || 0,
          row.highRiskEvents || 0,
          row.anomalyCount || 0,
          row.riskFactorsExplanation || "",
        ];

        // Context fields
        const contextFields = contextKeysArray.map((key) => {
          const value = row.context && row.context[key];
          return value !== undefined ? value : "";
        });

        return [...basicFields, ...contextFields]
          .map((field) => {
            // If the field is a string, escape any quotes and wrap in quotes
            if (typeof field === "string") {
              return `"${field.replace(/"/g, '""')}"`;
            }
            return field;
          })
          .join(",");
      })
      .join("\n");

    // Write to CSV file
    const csvContent = csvHeader + formattedRows;
    
    // Make sure the output directory exists
    const csvDir = path.dirname(config.SUMMARY_CSV);
    if (!fs.existsSync(csvDir)) {
      try {
        fs.mkdirSync(csvDir, { recursive: true });
        utils.log("info", `Created CSV output directory: ${csvDir}`);
      } catch (error) {
        throw new Error(`Failed to create CSV output directory: ${error.message}`);
      }
    }
    
    fs.writeFileSync(config.SUMMARY_CSV, csvContent);
    utils.log("info", `Generated CSV summary at ${config.SUMMARY_CSV}`);
  } catch (error) {
    utils.log("error", `Error generating CSV: ${error.message}`);
  }
}

/**
 * Generate a security report in HTML format
 * @param {Object} config - Application configuration
 * @param {Map<string, UserActivity>} userActivities - Map of userId -> UserActivity
 * @param {Object} options - Report options
 * @returns {Promise<string|null>} Path to the generated HTML report or null if failed
 */
async function generateReport(config, userActivities, options = {}) {
  try {
    // Check if HTML reporting is available
    if (!htmlReportGenerator) {
      throw new Error('HTML reporting dependencies not available. Install ejs package.');
    }
    
    // Validate userActivities
    if (!userActivities || typeof userActivities.forEach !== 'function') {
      utils.log("warn", "No valid user activities data available for report.");
      
      // If we have no valid user activities but still want to generate a minimal report,
      // create an empty Map to avoid errors
      if (!(userActivities instanceof Map)) {
        utils.log("info", "Creating minimal user activities data for report");
        userActivities = new Map();
      }
    }
    
    // Default output path based on config
    const outputPath = options.outputPath || 
                       path.join(path.dirname(config.SUMMARY_CSV), 'reports', 'security-report.html');
    
    // Create output directory if it doesn't exist
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      try {
        fs.mkdirSync(outputDir, { recursive: true });
        utils.log("info", `Created output directory: ${outputDir}`);
      } catch (error) {
        throw new Error(`Failed to create output directory: ${error.message}`);
      }
    }
    
    // Merge options with defaults
    const reportOptions = {
      title: options.title || 'DataDragon Security Analysis Report',
      dateRange: options.dateRange || `Analysis period: ${new Date().toLocaleDateString()}`,
      organization: options.organization || config.ORGANIZATION_NAME,
      scanDate: new Date(),
      ...options
    };
    
    // Generate the HTML report
    const result = await htmlReportGenerator.generateSecurityReport({
      userActivities,
      outputPath,
      reportOptions
    });
    
    utils.log("info", `Generated HTML security report at ${result.htmlPath}`);
    return result.htmlPath;
  } catch (error) {
    utils.log("error", `Error generating report: ${error.message}`);
    return null;
  }
}

/**
 * Check if HTML report generation is available
 * @returns {boolean} Whether HTML report generation is available
 */
function isReportingAvailable() {
  return htmlReportGenerator !== null;
}

function generateSummaryBanner(summary) {
  try {
    if (!summary || !summary.stats) return;

    const stats = summary.stats;
    const criticalWarnings = summary.stats.severeWarnings || 0;

    // Create banner content
    const bannerContent = [
      chalk.bold("DataDragon Security Analysis Summary"),
      "",
      `${chalk.cyan("Users Analyzed")}: ${stats.totalUsers}`,
      `${chalk.cyan("Event Logs Processed")}: ${stats.totalFiles}`,
      `${chalk.cyan("Security Warnings Detected")}: ${stats.totalWarnings}`,
      `${chalk.cyan("High Risk Users Identified")}: ${stats.highRiskUsers || 0}`,
      "",
      criticalWarnings > 0
        ? chalk.red(
            `⚠️  ${criticalWarnings} critical/high severity warnings detected!`
          )
        : chalk.green("✓ No critical security warnings detected"),
      "",
      `${chalk.cyan("Reports Generated")}:`,
      ` - JSON: ${config.SUMMARY_JSON}`,
      ` - CSV: ${config.SUMMARY_CSV}`,
    ];
    
    // Add HTML report status
    if (htmlReportGenerator) {
      bannerContent.push(` - HTML: ${stats.htmlPath || "Not generated yet"} (Print to PDF from browser)`);
    }

    // Display banner
    console.log(
      boxen(bannerContent.join("\n"), {
        padding: 1,
        margin: 1,
        borderStyle: "round",
        borderColor: "cyan",
      })
    );
  } catch (error) {
    utils.log("error", `Error displaying summary banner: ${error.message}`);
  }
}

module.exports = {
  generateSummary,
  generateSummaryBanner,
  generateReport,
  isReportingAvailable
};
