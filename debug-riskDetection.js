/**
 * Debug version of riskDetection.js with additional logging
 * Copy this to lib/riskDetection.js temporarily for debugging
 */

// Add this at the beginning of startProcessing function (around line 24)
async function startProcessing(tokens, options = {}) {
  console.log("🐲 DEBUG: Starting DataDragon processing...");
  console.log("🐲 DEBUG: Tokens available:", !!tokens);
  console.log("🐲 DEBUG: Options:", options);
  
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
      utils.log(
        "error",
        "No matching users found. Check your TARGET_USERS environment variable."
      );
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
      utils.log(
        "warn",
        "No login days found for monitored users in the specified time period."
      );

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

    // Continue with the rest of the processing...
    console.log("🐲 DEBUG: Continuing with log processing...");
    
    // [Rest of the function remains the same]
    
  } catch (error) {
    console.log("🐲 DEBUG: ERROR CAUGHT:", error.message);
    console.log("🐲 DEBUG: Error stack:", error.stack);
    utils.log("error", `Processing error: ${error.message}`);
    
    // [Rest of error handling remains the same]
  }
}
