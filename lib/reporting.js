// Enhanced report generation functionality
const fs = require("fs");
const path = require("path");
const chalk = require("chalk");
const boxen = require("boxen");
const config = require("../config/config");
const { riskConfig, sanitizeConfigForOutput } = require("../config/riskConfig");
const utils = require("./utils");

/**
 * Generate final summary report with enhanced user activity data
 * @param {Object} userMap - Map of user IDs to usernames
 * @param {Array} allScannedFiles - List of all scanned log files
 * @param {Array} allWarnings - List of all detected warnings
 * @param {Map} userActivities - Map of user IDs to UserActivity objects
 * @param {Object} riskCorrelations - Risk correlation analysis results
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

    // Process each user - whether they have warnings or not
    userActivities.forEach((activity, userId) => {
      const username = userMap[userId] || activity.username;

      // Get user's activity summary
      const activitySummary = activity.getSummary();

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
      fs.mkdirSync(jsonDir, { recursive: true });
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

      utils.log("info", chalk.cyan(`\nUser: ${username}`));
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
  } catch (error) {
    utils.log("error", `Error generating summary: ${error.message}`);
    console.error(error);
  }
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
    userActivities.forEach((activity, userId) => {
      // Get CSV data rows for this user
      const activityRows = activity.getCSVData();
      
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
    });

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
          row.riskFactorsExplanation ? formatWarningMessage(row.riskFactorsExplanation) : "No risk factors detected",
        ];

        // Add context fields in the same order as headers
        const contextFields = contextKeysArray.map((key) => {
          const value =
            row.context && row.context[key] !== undefined
              ? row.context[key]
              : "";
          return `"${String(value).replace(/"/g, '""')}"`;
        });

        // Combine and properly escape all fields
        return basicFields
          .map((field) => {
            if (field === null || field === undefined) return '""';
            return `"${String(field).replace(/"/g, '""')}"`;
          })
          .concat(contextFields)
          .join(",");
      })
      .join("\n");

    // Write the CSV file
    fs.writeFileSync(config.SUMMARY_CSV, csvHeader + formattedRows);
    utils.log("info", `Generated enhanced CSV report at ${config.SUMMARY_CSV}`);
  } catch (error) {
    utils.log("error", `Error generating CSV report: ${error.message}`);
  }
}

/**
 * Generate a visual summary banner showing scan results
 * @param {Object} summary - Summary object
 */
function generateSummaryBanner(summary) {
  const criticalCount = summary.stats.severeWarnings;
  const userCount = summary.stats.totalUsers;
  const filesCount = summary.stats.totalFiles;
  const totalWarnings = summary.stats.totalWarnings;
  const highRiskUsers = summary.highRiskUsers
    ? summary.highRiskUsers.length
    : 0;

  let riskStatus = "No Risk";
  let statusColor = chalk.green;

  // Determine risk level based on findings
  if (criticalCount > 0) {
    riskStatus = "CRITICAL RISK";
    statusColor = chalk.bgRed.white;
  } else if (totalWarnings > 10 || highRiskUsers > 0) {
    riskStatus = "HIGH RISK";
    statusColor = chalk.red;
  } else if (totalWarnings > 0) {
    riskStatus = "MEDIUM RISK";
    statusColor = chalk.yellow;
  } else {
    riskStatus = "LOW RISK";
    statusColor = chalk.blue;
  }

  // Display formatted summary box
  console.log(
    chalk.greenBright(
      boxen(
        `DataDragon Scan Complete\n\n` +
          `Monitored: ${userCount} users across ${filesCount} logs\n` +
          `Detected: ${totalWarnings} potential security risks\n` +
          (highRiskUsers > 0 ? `High-Risk Users: ${highRiskUsers}\n` : ``) +
          `Status: ${statusColor(riskStatus)}`,
        {
          padding: 1,
          borderStyle: "round",
          borderColor: "yellow",
          textAlignment: "center",
        }
      )
    )
  );
}

/**
 * Helper function to format warning messages for better readability in reports
 * @param {string} warning - Original warning message
 * @returns {string} Formatted warning message
 */
function formatWarningMessage(warning) {
  if (!warning) return "";
  
  // Always remove point values
  let formatted = warning.replace(/ \(\d+ points\)/, '');
  
  // Handle location change messages with the special prefix
  if (formatted.startsWith('LOCATION_CHANGE:')) {
    // Extract the locations and timing info
    const locationMatch = formatted.match(/: ([^:]+) to ([^(]+)(\([^)]+\))?/);
    if (locationMatch && locationMatch.length >= 3) {
      const fromLocation = locationMatch[1].trim();
      const toLocation = locationMatch[2].trim();
      const timeInfo = locationMatch[3] ? ` ${locationMatch[3].trim()}` : '';
      return `Suspicious login location change: ${fromLocation} to ${toLocation}${timeInfo}`;
    }
    
    // Fallback to simple replacement
    return formatted.replace(/^LOCATION_CHANGE: /, '')
                   .replace(/CRITICAL - .*?(Geographic|Suspicious) location change: /, 'Suspicious login location change: ');
  }
  
  // Handle geographic location changes that match the pattern
  if (formatted.includes('CRITICAL - Geographic location change:') || 
      formatted.includes('CRITICAL - Suspicious login location change:')) {
    
    // Extract the locations and timing info
    const locationMatch = formatted.match(/: ([^:]+) to ([^(]+)(\([^)]+\))?/);
    if (locationMatch && locationMatch.length >= 3) {
      const fromLocation = locationMatch[1].trim();
      const toLocation = locationMatch[2].trim();
      const timeInfo = locationMatch[3] ? ` ${locationMatch[3].trim()}` : '';
      return `Suspicious login location change: ${fromLocation} to ${toLocation}${timeInfo}`;
    }
    
    // Fallback to simple replacement
    return formatted
            .replace(/CRITICAL - .*?(Geographic|Suspicious) location change: /, 'Suspicious login location change: ');
  }
  
  // For all other messages, just remove the Warning prefix if present
  return formatted.replace(/^Warning - /, '');
}

module.exports = {
  generateSummary,
  generateSummaryBanner,
};
