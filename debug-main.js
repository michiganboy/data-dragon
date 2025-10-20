/**
 * Debug version of the main entry point
 * Copy the relevant parts to index.js temporarily
 */

require("dotenv").config();
const chalk = require("chalk");
const boxen = require("boxen");
const fs = require("fs");
const path = require("path");

// Import required modules
const config = require("./config/config");
const { interactiveAuth } = require("./lib/auth");
const { loadTargetUsers } = require("./lib/userLoader");
const { startProcessing } = require("./lib/riskDetection");
const { displayBanner } = require("./lib/utils");

/**
 * Main application function with debug logging
 */
async function main() {
  try {
    console.log("🐲 DEBUG: Starting main application...");
    
    // Process command line arguments
    const args = process.argv.slice(2);
    const options = parseCommandLineArgs(args);
    console.log("🐲 DEBUG: Command line options:", options);

    // Apply debug logging if requested
    if (options.debug) {
      process.env.LOG_LEVEL = "debug";
      console.log(chalk.cyan("[INFO] Debug logging enabled"));
    }

    // Load custom risk config if specified
    if (options.config) {
      console.log("🐲 DEBUG: Loading custom risk config...");
      const riskConfig = require("./config/riskConfig");
      riskConfig.loadCustomConfig(options.config);
    }

    // Display banner
    console.log("🐲 DEBUG: Displaying banner...");
    displayBanner();

    // Get authentication tokens
    console.log("🐲 DEBUG: Starting authentication...");
    const tokens = await interactiveAuth();
    console.log("🐲 DEBUG: Authentication successful:", !!tokens);

    // Start processing with tokens and options
    console.log("🐲 DEBUG: Starting main processing...");
    await startProcessing(tokens, options);
    console.log("🐲 DEBUG: Main processing completed successfully!");
    
  } catch (error) {
    console.log("🐲 DEBUG: ERROR in main function:", error.message);
    console.log("🐲 DEBUG: Error stack:", error.stack);
    console.error(
      chalk.red("[ERROR] DataDragon encountered an error:"),
      error.message
    );
    process.exit(1);
  }
}

/**
 * Parses command line arguments into options object
 */
function parseCommandLineArgs(args) {
  let options = {
    mode: "production",
    config: null,
    output: null,
    filter: null,
    startDate: null,
    endDate: null,
    maxDays: 30,
    correlationWindow: 2,
    noUserActivity: false,
  };

  args.forEach((arg) => {
    if (arg === "--debug") {
      options.debug = true;
    } else if (arg.startsWith("--days=")) {
      const days = parseInt(arg.split("=")[1], 10);
      if (!isNaN(days)) {
        options.days = days;
      }
    } else if (arg.startsWith("--config=")) {
      options.config = arg.split("=")[1];
    } else if (arg.startsWith("--output=")) {
      options.output = arg.split("=")[1];
    } else if (arg.startsWith("--correlation-window=")) {
      const window = parseFloat(arg.split("=")[1]);
      if (!isNaN(window)) {
        options.correlationWindow = window;
      }
    } else if (arg === "--no-user-activity") {
      options.noUserActivity = true;
    }
  });

  return options;
}

// Run the main function
main();
