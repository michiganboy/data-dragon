/**
 * Risk Detection Module
 * Analyzes event logs for security risks and performs user activity analysis
 */
const axios = require("axios");
const chalk = require("chalk");
const config = require("../config/config");
const { riskConfig } = require("../config/riskConfig");
const { fetchUserMap } = require("./userLoader");
const LoginDataManager = require("./loginDataManager");
const RiskCorrelation = require("./riskCorrelation");
const utils = require("./utils");
const LogProcessor = require("../models/log");
const path = require("path");

// Global state for risk detection
let userMap = {}; // Maps userId to username (email)
const allWarnings = [];
const riskCounters = {};
let loginDataManager = null;
let riskCorrelation = null;

// Enhanced startProcessing with user activity analysis
async function startProcessing(tokens, options = {}) {
  utils.log("info", "DataDragon awakens — guardian of the Salesforce hoard");

  const headers = { Authorization: `Bearer ${tokens.access_token}` };
  const instance_url = tokens.instance_url || config.SF_LOGIN_URL;

  try {
    // Step 1: Map email addresses to user IDs
    userMap = await fetchUserMap(headers, instance_url);
    const userIds = Object.keys(userMap);

    if (userIds.length === 0) {
      utils.log(
        "error",
        "No matching users found. Check your TARGET_USERS environment variable."
      );
      return;
    }

    utils.log("info", `Found ${userIds.length} users to monitor:`);
    Object.entries(userMap).forEach(([id, email]) => {
      utils.log("info", `   - ${email} (${id})`);
    });

    // Step 2: Initialize the Login Data Manager
    loginDataManager = new LoginDataManager(config);

    // Step 3: Fetch detailed login history with advanced user activity tracking
    const loginData = await loginDataManager.fetchLoginHistory(
      headers,
      userMap,
      instance_url,
      options.days || null
    );

    const userActivities = loginData.userActivities;
    const loginDays = loginData.allLoginDays;

    if (loginDays.length === 0) {
      utils.log(
        "warn",
        "No login days found for monitored users in the specified time period."
      );

      // Generate report even with no login days
      const reporting = require("./reporting");
      reporting.generateSummary(config, userActivities, userMap);
      
      // Generate PDF report if requested
      if (options.pdf) {
        await generatePDFReport(config, userActivities, options.pdfOptions);
      }
      
      return;
    }

    utils.log(
      "info",
      `Tracking ${loginDays.length} login days where monitored users were active.`
    );

    // Step 4: Fetch relevent event logs
    const query = `SELECT Id,LogFile,EventType,LogDate FROM EventLogFile 
               WHERE EventType IN (
                 'ReportExport', 
                 'LoginAs', 
                 'ContentDistribution',
                 'DocumentAttachmentDownloads',
                 'ApexExecution',
                 'BulkApiRequest',
                 'PermissionSetAssignment',
                 'ApiAnomalyEventStore',
                 'DataExport',
                 'ContentDocumentLink',
                 'SetupAuditTrail',
                 'SetupEntityAccess',
                 'Login',
                 'Logout',
                 'URI',
                 'LightningPageView',
                 'VisualforceRequest',
                 'RestAPI',
                 'ApexCallout',
                 'Search',
                 'Dashboard',
                 'AuraRequest',
                 'ReportRun',
                 'FlowExecution'
               )
               ORDER BY LogDate DESC`;
    const { data } = await axios.get(
      `${instance_url}/services/data/v57.0/query?q=${encodeURIComponent(
        query
      )}`,
      { headers }
    );

    utils.log(
      "info",
      `Found ${data.records.length} event logs available to scan.`
    );

    // Step 5: Process relevant logs
    let processedLogs = 0;
    let relevantLogs = data.records.filter((log) => {
      const logDate = log.LogDate.split("T")[0];
      return loginDays.includes(logDate);
    });

    // Apply scan limit if specified in env
    const scanLimit = config.SCAN_LIMIT;

    if (scanLimit && !isNaN(scanLimit) && scanLimit > 0) {
      relevantLogs = relevantLogs.slice(0, scanLimit);
      utils.log(
        "info",
        `Limiting scan to ${scanLimit} logs due to SCAN_LIMIT setting`
      );
    }

    utils.log(
      "info",
      `Processing ${relevantLogs.length} logs relevant to monitored users.`
    );

    // Initialize log processor and risk detection
    const logProcessor = new LogProcessor(userMap, {
      checkForRisks: (row, eventType) => checkForRisks(row, eventType),
    });

    // Process logs in batches to avoid overwhelming memory
    const BATCH_SIZE = config.BATCH_SIZE || 5;

    for (let i = 0; i < relevantLogs.length; i += BATCH_SIZE) {
      const batch = relevantLogs.slice(i, i + BATCH_SIZE);
      utils.log(
        "info",
        `Processing batch ${Math.floor(i / BATCH_SIZE) + 1} of ${Math.ceil(
          relevantLogs.length / BATCH_SIZE
        )}`
      );

      // Process batch concurrently
      await Promise.all(
        batch.map((logFile) => {
          const logDate = logFile.LogDate.split("T")[0];
          return processLogWithActivity(
            logFile,
            tokens,
            logDate,
            headers,
            logProcessor
          );
        })
      );

      processedLogs += batch.length;
    }

    utils.log(
      "info",
      `Processed ${processedLogs} logs relevant to monitored users.`
    );

    // Step 6: Add all warnings to user activities
    loginDataManager.addWarnings(allWarnings);

    // Step 7: Perform risk correlation analysis
    utils.log(
      "info",
      "Analyzing risk correlations between login patterns and security events..."
    );
    riskCorrelation = new RiskCorrelation(userActivities);
    const correlationResults = riskCorrelation.analyzeAll();

    // Get high risk users from correlation analysis
    const highRiskUsers = riskCorrelation.getHighRiskUsers();
    if (highRiskUsers.length > 0) {
      utils.log(
        "info",
        chalk.red(
          `Identified ${highRiskUsers.length} high-risk users based on behavior analysis`
        )
      );

      highRiskUsers.forEach((user) => {
        utils.log(
          "info",
          chalk.yellow(
            `   - ${user.username} (Risk Score: ${user.correlationScore.toFixed(
              1
            )})`
          )
        );
      });
    }

    // Step 8: Generate enhanced summary with user activity data
    const reporting = require("./reporting");
    const allScannedFiles = logProcessor.getScannedFiles();
    const summaryData = reporting.generateSummary(
      userMap,
      allScannedFiles,
      allWarnings,
      userActivities,
      riskCorrelation
    );
    
    // Display summary banner if it wasn't shown already
    console.log("\n" + "=".repeat(80) + "\n");
    reporting.generateSummaryBanner(summaryData);

    // Step 9: Generate PDF report automatically
    try {
      if (reporting.isPDFReportingAvailable()) {
        // Set date range for the report
        const pdfOptions = {
          ...options.pdfOptions, // Any options from command line
          dateRange: `Analysis period: ${loginDays[0]} to ${loginDays[loginDays.length - 1]}`
        };
        
        // Generate the PDF report
        await reporting.generatePDFReport(config, userActivities, pdfOptions);
      } else {
        utils.log(
          "warn",
          "PDF report generation not available. Install required packages (pdfkit)."
        );
      }
    } catch (pdfError) {
      utils.log("error", `Error generating PDF report: ${pdfError.message}`);
    }
  } catch (error) {
    utils.log("error", `Processing error: ${error.message}`);
    if (error.response) {
      utils.log(
        "error",
        `Response data: ${JSON.stringify(error.response.data)}`
      );
    }

    // Even with an error, generate a report with available data
    try {
      // Create minimal user activities if they're not available
      let userActivitiesMap = loginDataManager
        ? loginDataManager.getUserActivities()
        : createMinimalUserActivities(userMap);

      const reporting = require("./reporting");
      const minimalScannedFiles = logProcessor ? logProcessor.getScannedFiles() : [];
      const errorSummaryData = reporting.generateSummary(
        userMap,
        minimalScannedFiles,
        allWarnings,
        userActivitiesMap,
        null // No correlation data in error case
      );
      
      // Display minimal summary in case of error
      console.log("\n" + "=".repeat(80) + "\n");
      reporting.generateSummaryBanner(errorSummaryData);
      
      // Try to generate PDF report with minimal data
      if (reporting.isPDFReportingAvailable()) {
        await reporting.generatePDFReport(config, userActivitiesMap, options.pdfOptions);
      }
    } catch (reportingError) {
      utils.log(
        "error",
        `Failed to generate report: ${reportingError.message}`
      );
    }
  }
}

/**
 * Generate PDF report with appropriate error handling
 * @param {Object} config - Application configuration
 * @param {Map<string, Object>} userActivities - User activities map
 * @param {Object} pdfOptions - PDF report options
 */
async function generatePDFReport(config, userActivities, pdfOptions = {}) {
  try {
    const reporting = require("./reporting");
    if (!reporting.isPDFReportingAvailable()) {
      utils.log(
        "error",
        "PDF report generation not available. Install required packages (pdfkit, chart.js, chartjs-node-canvas)."
      );
      return null;
    }
    
    // Set default output path if not specified
    if (!pdfOptions.outputPath) {
      pdfOptions.outputPath = path.join(process.cwd(), "output/reports", "security-report.pdf");
    }
    
    // Generate the PDF report
    const pdfPath = await reporting.generatePDFReport(config, userActivities, pdfOptions);
    
    if (pdfPath) {
      utils.log("info", chalk.green(`PDF report generated successfully at: ${pdfPath}`));
    }
    
    return pdfPath;
  } catch (error) {
    utils.log("error", `Error generating PDF report: ${error.message}`);
    return null;
  }
}

/**
 * Process a log file with user activity tracking
 * @param {Object} logFile - Log file record from Salesforce
 * @param {Object} tokens - Authentication tokens
 * @param {string} logDate - Log date string
 * @param {Object} headers - HTTP headers
 * @param {LogProcessor} logProcessor - Log processor instance
 * @returns {Promise} Promise resolving when processing is complete
 */
async function processLogWithActivity(
  logFile,
  tokens,
  logDate,
  headers,
  logProcessor
) {
  try {
    // Standard log processing
    const processedUsers = await logProcessor.processLog(
      logFile,
      tokens,
      logDate,
      headers
    );

    // Update user activities with info about which logs were scanned
    if (loginDataManager && processedUsers && processedUsers.length > 0) {
      loginDataManager.recordScannedLog(
        logFile.EventType,
        logDate,
        processedUsers
      );
    }

    return processedUsers;
  } catch (error) {
    utils.log(
      "error",
      `Error processing log ${logFile.EventType}: ${error.message}`
    );
    return [];
  }
}

/**
 * Create minimal user activity objects when normal initialization fails
 * @param {Object} userMap - Map of userId -> username
 * @returns {Map} Map of userId -> UserActivity
 */
function createMinimalUserActivities(userMap) {
  const UserActivity = require("../models/userActivity");
  const activities = new Map();

  Object.entries(userMap).forEach(([userId, username]) => {
    activities.set(userId, new UserActivity(userId, username));
  });

  return activities;
}

// Enhanced risk detection logic with advanced pattern recognition
function checkForRisks(row, eventType) {
  // Skip if event type isn't in our risk configuration
  if (!riskConfig[eventType]) return;

  const config = riskConfig[eventType];

  // Get standardized fields
  const standardFields = utils.getStandardFields(row);

  const userKey = `${standardFields.userId}-${standardFields.date}`;
  const sessionKey = standardFields.sessionKey;
  const hourKey = `${standardFields.date}-${new Date(
    standardFields.timestamp || ""
  ).getHours()}`;

  // Initialize counter objects if they don't exist
  riskCounters[userKey] = riskCounters[userKey] || {};
  riskCounters[userKey].sessions = riskCounters[userKey].sessions || {};
  riskCounters[userKey].sessions[sessionKey] =
    riskCounters[userKey].sessions[sessionKey] || {};
  riskCounters[userKey].hours = riskCounters[userKey].hours || {};
  riskCounters[userKey].hours[hourKey] =
    riskCounters[userKey].hours[hourKey] || {};
  
  // Track if alerts have been issued for specific event types to prevent duplicates
  riskCounters[userKey].alertedEvents = riskCounters[userKey].alertedEvents || {};

  // Determine which counter to use based on configured time window
  let counterGroup;
  switch (config.timeWindow) {
    case "session":
      counterGroup = riskCounters[userKey].sessions[sessionKey];
      break;
    case "hour":
      counterGroup = riskCounters[userKey].hours[hourKey];
      break;
    case "day":
    default:
      counterGroup = riskCounters[userKey];
      break;
  }

  // Also set up alerting flags in the appropriate counter group
  counterGroup.alertedEvents = counterGroup.alertedEvents || {};

  // Special handling for ApexExecution to only count high-risk quiddity types
  if (eventType === 'ApexExecution' && config.countField === 'QUIDDITY') {
    const quiddity = row.QUIDDITY || '';
    // Only these types are considered high risk (must match definition in riskConfig.js)
    const highRiskTypes = ['A', 'X', 'W'];
    
    // Skip low-risk types entirely
    if (!highRiskTypes.includes(quiddity)) {
      return;
    }
  }

  // Increment appropriate counter
  if (config.countField) {
    // Use standardized fields for common issues
    let fieldValue = "unknown";

    // Special handling for fields with known standardization issues
    if (config.countField === "URL" || config.countField === "ENDPOINT_URL") {
      fieldValue = standardFields.endpointUrl || row[config.countField] || "unknown";
    } 
    else if (config.countField === "COMPONENT_TYPE" || config.countField === "COMPONENT_NAME") {
      fieldValue = standardFields.componentName || row[config.countField] || "unknown";
    }
    else if (config.countField === "LINKED_ENTITY_ID" || config.countField === "RELATED_RECORD_ID") {
      fieldValue = standardFields.linkedEntityId || row[config.countField] || "unknown";
    }
    else if (config.countField === "SHARED_WITH_ENTITY_ID") {
      fieldValue = standardFields.sharedWithEntity || row[config.countField] || "unknown";
      
      // Try to add name information when available
      if (fieldValue !== "unknown" && standardFields.sharedWithName) {
        fieldValue = `${standardFields.sharedWithName} (${fieldValue})`;
      }
    }
    else if (config.countField === "DASHBOARD_ID") {
      fieldValue = standardFields.dashboardId || row[config.countField] || "unknown";
    }
    else if (config.countField === "DOCUMENT_ID" || config.countField === "CONTENT_ID") {
      fieldValue = standardFields.documentId || row[config.countField] || "unknown";
    }
    else if (config.countField === "ACTION" || config.countField === "METHOD" || config.countField === "OPERATION_TYPE") {
      fieldValue = standardFields.action || row[config.countField] || "unknown";
    }
    else {
      // Default case - use the field directly from the row
      fieldValue = row[config.countField] || "unknown";
    }

    const counterKey = `${eventType}-${fieldValue}`;
    counterGroup[counterKey] = (counterGroup[counterKey] || 0) + 1;

    // Check if threshold is reached for this specific value and we haven't alerted yet
    const alertKey = `${counterKey}`;
    if (counterGroup[counterKey] >= config.threshold && !counterGroup.alertedEvents[alertKey]) {
      // Mark this event type as already alerted
      counterGroup.alertedEvents[alertKey] = true;
      
      // Basic risk detection based on threshold
      const warning = `${config.description} (${fieldValue})`;
      logRisk(userKey, row, warning, config.severity);
    }
  } else {
    // Simple counter without field distinction
    const counterKey = eventType;
    counterGroup[counterKey] = (counterGroup[counterKey] || 0) + 1;

    // Check threshold and whether we've already alerted
    const alertKey = counterKey;
    if (counterGroup[counterKey] >= config.threshold && !counterGroup.alertedEvents[alertKey]) {
      // Mark this event type as already alerted
      counterGroup.alertedEvents[alertKey] = true;
      
      logRisk(userKey, row, config.description, config.severity);
    }
  }

  // Run any custom detection logic defined for this event type
  // Custom detection can still run and has its own tracking for alerts
  if (config.customDetection && typeof config.customDetection === "function") {
    try {
      const customResult = config.customDetection(row);
      if (customResult) {
        const { customMessage, severityMultiplier } = customResult;
        // Calculate enhanced severity if a multiplier is provided
        const enhancedSeverity = severityMultiplier
          ? utils.enhanceSeverity(config.severity, severityMultiplier)
          : config.severity;

        logRisk(
          userKey,
          row,
          customMessage || config.description,
          enhancedSeverity
        );
      }
    } catch (error) {
      utils.log(
        "error",
        `Error in custom risk detection for ${eventType}: ${error.message}`
      );
    }
  }
}

// Enhanced risk logging function with user activity integration
function logRisk(userKey, row, warning, severity = "medium") {
  // Get standardized fields
  const standardFields = utils.getStandardFields(row);

  // Extract useful fields from row for context
  const userId = standardFields.userId;
  const username = userMap[userId] || standardFields.username || "Unknown User";
  const timestamp = standardFields.timestamp;
  const eventType = standardFields.eventType;

  // Create warning object with enhanced metadata
  const warningObj = {
    user: username,
    userId: userId,
    date: standardFields.date,
    timestamp: timestamp,
    warning,
    severity,
    eventType,
    sessionKey: standardFields.sessionKey,
    clientIp: standardFields.clientIp,
    context: {}, // Will hold relevant context fields
  };

  // Add relevant context fields from the row
  const contextFieldPriority = [
    "RECORDS_PROCESSED",
    "URI",
    "ACTION",
    "ENTITY_NAME",
    "DELEGATED_USERNAME",
    "DASHBOARD_ID",
    "QUERY_STRING",
    "PAGE_NAME",
    "COMPONENT_NAME",
    "ENDPOINT_URL",
    "FLOW_NAME",
    "APEX_CLASS_NAME",
    "FILE_TYPE",
    "RELATED_RECORD_ID",
    "QUIDDITY", // Add QUIDDITY field for ApexExecution events
  ];

  // Add only non-empty fields to context
  contextFieldPriority.forEach((field) => {
    if (row[field]) {
      warningObj.context[field] = row[field];
    }
  });

  // For ApexExecution events, ensure we add a message about the quiddity code
  if (eventType === 'ApexExecution' && row.QUIDDITY) {
    const quiddityMap = {
      'A': 'Anonymous Apex',
      'B': 'Batch Apex',
      'F': 'Future Method',
      'H': 'Scheduled Apex',
      'I': 'Inbound Email',
      'L': 'Lightning',
      'M': 'Remote Action',
      'Q': 'Queueable Apex',
      'R': 'Regular Apex',
      'S': 'Scheduled Apex',
      'T': 'Trigger',
      'V': 'Visualforce',
      'W': 'Web Service',
      'X': 'Execute Anonymous'
    };
    
    const executionType = quiddityMap[row.QUIDDITY] || 'Unknown Type';
    warningObj.warning = `${warning} - ${executionType} (${row.QUIDDITY})`;
  }
  
  // Process location change warnings specially
  if (warning.includes("Suspicious login location change") || warning.includes("Login from different locations")) {
    eventType = "LocationChange";
    severity = "critical";
    warningObj.priority = true;
  }

  // Add the warning
  if (!allWarnings.some(w => w.warning === warning && w.userId === userId)) {
    allWarnings.push(warningObj);
    
    // Log with severity as prefix for proper formatting and coloring
    utils.log(
      "risk",
      `${severity} ${warningObj.warning} [${userId ? userMap[userId] || userId : "Unknown"}]`
    );
  }
}

module.exports = {
  startProcessing,
  checkForRisks,
  allWarnings,
  userMap,
  loginDataManager,
  riskCorrelation,
};
