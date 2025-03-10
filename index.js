// Enhanced main entry point for DataDragon with user activity tracking
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

// Ensure directories exist
const ensureDirectoriesExist = () => {
  const dirs = [
    path.join(process.cwd(), "output"),
    path.join(process.cwd(), "output/eventLogs"),
  ];

  dirs.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};

// Create necessary directories
ensureDirectoriesExist();

// Main function with enhanced CLI options
async function main() {
  try {
    // Process command line arguments
    const args = process.argv.slice(2);
    const options = parseCommandLineArgs(args);

    // Apply debug logging if requested
    if (options.debug) {
      process.env.LOG_LEVEL = "debug";
      console.log(chalk.cyan("[INFO] Debug logging enabled"));
    }

    // Load custom risk config if specified
    if (options.config) {
      const riskConfig = require("./config/riskConfig");
      riskConfig.loadCustomConfig(options.config);
    }

    // Display banner
    displayBanner();

    // Get authentication tokens (from cached file or web flow)
    const tokens = await interactiveAuth();

    // Start processing with tokens and options
    await startProcessing(tokens, options);
  } catch (error) {
    console.error(
      chalk.red("[ERROR] DataDragon encountered an error:"),
      error.message
    );
    process.exit(1);
  }
}

// Parse command line arguments with enhanced options
function parseCommandLineArgs(args) {
  const options = {
    debug: false,
    days: null,
    config: null,
    output: null,
    correlationWindow: 2, // Hours to look for correlations between login anomalies and security events
    noUserActivity: false, // Option to disable user activity analysis for troubleshooting
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
