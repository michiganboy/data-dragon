/**
 * Enhanced debug version of riskDetection.js
 * Add these console.log statements to your lib/riskDetection.js file
 */

// Add these debug statements at key points in startProcessing function:

async function startProcessing(tokens, options = {}) {
  console.log("🐲 DEBUG: startProcessing called with options:", options);
  
  utils.log("info", "DataDragon awakens — guardian of the Salesforce hoard");

  const headers = { Authorization: `Bearer ${tokens.access_token}` };
  const instance_url = tokens.instance_url || config.SF_LOGIN_URL;

  try {
    // Step 1: Map email addresses to user IDs
    console.log("🐲 DEBUG: Step 1 - Fetching user map...");
    userMap = await fetchUserMap(headers, instance_url);
    console.log("🐲 DEBUG: User map result:", Object.keys(userMap).length, "users");
    
    const userIds = Object.keys(userMap);

    if (userIds.length === 0) {
      console.log("🐲 DEBUG: ERROR - No users found!");
      utils.log("error", "No matching users found. Check your TARGET_USERS environment variable.");
      return;
    }

    // Step 2: Initialize the Login Data Manager
    console.log("🐲 DEBUG: Step 2 - Initializing login data manager...");
    loginDataManager = new LoginDataManager(config);

    // Step 3: Fetch detailed login history
    console.log("🐲 DEBUG: Step 3 - Fetching login history...");
    const loginData = await loginDataManager.fetchLoginHistory(
      headers,
      userMap,
      instance_url,
      options.days || null
    );

    const userActivities = loginData.userActivities;
    const loginDays = loginData.allLoginDays;
    
    console.log("🐲 DEBUG: Login data result:");
    console.log("  - User activities:", userActivities ? userActivities.size : "null");
    console.log("  - Login days:", loginDays ? loginDays.length : "null");

    if (loginDays.length === 0) {
      console.log("🐲 DEBUG: No login days found - generating minimal report");
      utils.log("warn", "No login days found for monitored users in the specified time period.");

      // Generate report even with no login days
      console.log("🐲 DEBUG: Calling generateSummary...");
      const reporting = require("./reporting");
      const summaryResult = reporting.generateSummary(userMap, [], [], userActivities);
      console.log("🐲 DEBUG: Summary generation result:", !!summaryResult);
      
      // Generate HTML report if requested
      if (options.pdf) {
        console.log("🐲 DEBUG: Generating HTML report...");
        await generateHTMLReport(config, userActivities);
      }
      
      console.log("🐲 DEBUG: Early return from no login days");
      return;
    }

    utils.log("info", `Tracking ${loginDays.length} login days where monitored users were active.`);

    // Step 4: Fetch relevant event logs
    console.log("🐲 DEBUG: Step 4 - Fetching event logs...");
    const query = `SELECT Id,LogFile,EventType,LogDate FROM EventLogFile 
               WHERE EventType IN (
                 'ReportExport', 
                 'LoginAs', 
                 'ContentDistribution',
                 'DocumentAttachmentDownloads',
                 'ContentTransfer',
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
      `${instance_url}/services/data/v57.0/query?q=${encodeURIComponent(query)}`,
      { headers }
    );

    console.log("🐲 DEBUG: Event logs query result:", data.records ? data.records.length : "null");
    utils.log("info", `Found ${data.records.length} event logs available to scan.`);

    // Step 5: Process relevant logs
    console.log("🐲 DEBUG: Step 5 - Processing logs...");
    let processedLogs = 0;
    let relevantLogs = data.records.filter((log) => {
      const logDate = log.LogDate.split("T")[0];
      return loginDays.includes(logDate);
    });

    console.log("🐲 DEBUG: Relevant logs found:", relevantLogs.length);

    // Apply scan limit if specified in env
    const scanLimit = config.SCAN_LIMIT;
    if (scanLimit && !isNaN(scanLimit) && scanLimit > 0) {
      relevantLogs = relevantLogs.slice(0, scanLimit);
      console.log("🐲 DEBUG: Applied scan limit:", scanLimit);
    }

    utils.log("info", `Processing ${relevantLogs.length} logs relevant to monitored users.`);

    // Initialize log processor and risk detection
    console.log("🐲 DEBUG: Initializing log processor...");
    const logProcessor = new LogProcessor(userMap, {
      checkForRisks: (row, eventType) => checkForRisks(row, eventType),
    });

    // Process logs in batches
    const BATCH_SIZE = config.BATCH_SIZE || 5;
    console.log("🐲 DEBUG: Processing in batches of:", BATCH_SIZE);

    for (let i = 0; i < relevantLogs.length; i += BATCH_SIZE) {
      const batch = relevantLogs.slice(i, i + BATCH_SIZE);
      console.log("🐲 DEBUG: Processing batch", Math.floor(i / BATCH_SIZE) + 1, "of", Math.ceil(relevantLogs.length / BATCH_SIZE));
      
      utils.log("info", `Processing batch ${Math.floor(i / BATCH_SIZE) + 1} of ${Math.ceil(relevantLogs.length / BATCH_SIZE)}`);

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

    console.log("🐲 DEBUG: Log processing completed. Processed:", processedLogs);
    utils.log("info", `Processed ${processedLogs} logs relevant to monitored users.`);

    // Step 6: Add all warnings to user activities
    console.log("🐲 DEBUG: Step 6 - Adding warnings to user activities...");
    loginDataManager.addWarnings(allWarnings);

    // Step 7: Perform risk correlation analysis
    console.log("🐲 DEBUG: Step 7 - Performing risk correlation analysis...");
    utils.log("info", "Analyzing risk correlations between login patterns and security events...");
    riskCorrelation = new RiskCorrelation(userActivities);
    const correlationResults = riskCorrelation.analyzeAll();

    // Get high risk users from correlation analysis
    const highRiskUsers = riskCorrelation.getHighRiskUsers();
    console.log("🐲 DEBUG: High risk users found:", highRiskUsers.length);
    
    if (highRiskUsers.length > 0) {
      utils.log("info", chalk.red(`Identified ${highRiskUsers.length} high-risk users based on behavior analysis`));
      highRiskUsers.forEach((user) => {
        utils.log("info", chalk.yellow(`   - ${user.username} (Risk Score: ${user.correlationScore.toFixed(1)})`));
      });
    }

    // Step 8: Generate enhanced summary with user activity data
    console.log("🐲 DEBUG: Step 8 - Generating summary...");
    const reporting = require("./reporting");
    const allScannedFiles = logProcessor.getScannedFiles();
    const summaryData = reporting.generateSummary(
      userMap,
      allScannedFiles,
      allWarnings,
      userActivities,
      riskCorrelation
    );
    
    console.log("🐲 DEBUG: Summary generation completed:", !!summaryData);
    
    // Display summary banner if it wasn't shown already
    console.log("\n" + "=".repeat(80) + "\n");
    reporting.generateSummaryBanner(summaryData);

    // Step 9: Generate HTML report automatically
    console.log("🐲 DEBUG: Step 9 - Generating HTML report...");
    try {
      if (reporting.isReportingAvailable()) {
        console.log("🐲 DEBUG: HTML reporting is available");
        // Set date range for the report
        const reportOptions = {
          title: 'DataDragon Security Analysis Report',
          dateRange: `Analysis period: ${loginDays[0]} to ${loginDays[loginDays.length - 1]}`,
          organization: config.ORGANIZATION_NAME || 'Your Organization'
        };
        
        // Generate the HTML report
        console.log("🐲 DEBUG: Calling generateReport...");
        await reporting.generateReport(config, userActivities, reportOptions);
        console.log("🐲 DEBUG: HTML report generation completed");
      } else {
        console.log("🐲 DEBUG: HTML reporting not available");
        utils.log("warn", "HTML report generation not available. Install required packages (ejs).");
      }
    } catch (reportError) {
      console.log("🐲 DEBUG: Error in HTML report generation:", reportError.message);
      utils.log("error", `Error generating HTML report: ${reportError.message}`);
    }
    
    console.log("🐲 DEBUG: startProcessing completed successfully!");
    
  } catch (error) {
    console.log("🐲 DEBUG: ERROR in startProcessing:", error.message);
    console.log("🐲 DEBUG: Error stack:", error.stack);
    utils.log("error", `Processing error: ${error.message}`);
    
    if (error.response) {
      utils.log("error", `Response data: ${JSON.stringify(error.response.data)}`);
    }

    // Even with an error, generate a report with available data
    try {
      console.log("🐲 DEBUG: Attempting to generate error report...");
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
      
      // Try to generate report with minimal data
      if (reporting.isReportingAvailable()) {
        const reportOptions = {
          title: 'DataDragon Security Analysis Report',
          organization: config.ORGANIZATION_NAME || 'Your Organization'
        };
        await reporting.generateReport(config, userActivitiesMap, reportOptions);
      }
    } catch (reportingError) {
      console.log("🐲 DEBUG: Error in error reporting:", reportingError.message);
      utils.log("error", `Failed to generate report: ${reportingError.message}`);
    }
  }
}
