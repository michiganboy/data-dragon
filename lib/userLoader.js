/**
 * User Loading Module
 * Handles loading and mapping target users from various sources
 */
const fs = require("fs");
const chalk = require("chalk");
const csvParser = require("csv-parser");
const { Readable } = require("stream");
const axios = require("axios");
const config = require("../config/config");
const utils = require("./utils"); // Import full utils object

/**
 * Loads target users from CSV file or environment variable
 * @returns {Promise<Array<string>>} Array of target usernames/emails
 */
async function loadTargetUsers() {
  let targetUsers = [];

  // Try to load from CSV file first
  if (fs.existsSync(config.USERS_CSV)) {
    try {
      utils.log("info", `Loading target users from ${config.USERS_CSV}`);

      // Read and parse CSV file
      const fileContent = fs.readFileSync(config.USERS_CSV, "utf8");

      // Use csv-parser to properly handle CSV
      return new Promise((resolve, reject) => {
        const users = [];
        const parser = csvParser();

        parser.on("data", (row) => {
          // Check for email field or first column
          const email =
            row.email ||
            row.Email ||
            row.USERNAME ||
            row.username ||
            Object.values(row)[0];
          if (email && typeof email === "string" && email.includes("@")) {
            users.push(email.trim().toLowerCase());
          }
        });

        parser.on("end", () => {
          utils.log("info", `Loaded ${users.length} users from CSV file`);
          resolve(users);
        });

        parser.on("error", (err) => {
          utils.log("error", `Error parsing CSV: ${err.message}`);
          reject(err);
        });

        // Feed the CSV content to the parser
        const s = new Readable();
        s.push(fileContent);
        s.push(null);
        s.pipe(parser);
      });
    } catch (error) {
      utils.log("error", `Error reading users CSV: ${error.message}`);
      utils.log("warn", "Falling back to TARGET_USERS environment variable");
    }
  }

  // Fall back to environment variable
  if (config.TARGET_USERS) {
    targetUsers = config.TARGET_USERS.split(",").map((u) =>
      u.trim().toLowerCase()
    );
    utils.log(
      "info",
      `Loaded ${targetUsers.length} users from environment variable`
    );
  } else {
    utils.log(
      "warn",
      "No target users specified. Please add users to TARGET_USERS env variable or provide a target-users.csv file."
    );
  }

  return targetUsers;
}

/**
 * Fetches user mapping from Salesforce User object
 * @param {Object} headers - HTTP headers with auth token
 * @param {string} instance_url - Salesforce instance URL
 * @returns {Promise<Object>} Map of userId -> username
 */
async function fetchUserMap(headers, instance_url) {
  utils.log("info", "Fetching user information...");

  try {
    // First load target users from CSV or env
    const targetUsernames = await loadTargetUsers();

    if (targetUsernames.length === 0) {
      throw new Error(
        "No target users specified. Add users to TARGET_USERS env variable or provide a target-users.csv file."
      );
    }

    // Format the query properly with quotes around each email
    const formattedEmails = targetUsernames
      .map((email) => `'${email}'`)
      .join(",");
    const query = `SELECT Id, Username FROM User WHERE Username IN (${formattedEmails})`;

    const { data } = await axios.get(
      `${instance_url}/services/data/v57.0/query?q=${encodeURIComponent(
        query
      )}`,
      { headers }
    );

    const map = {};
    data.records.forEach((user) => {
      map[user.Id] = user.Username.toLowerCase();
    });

    if (Object.keys(map).length < targetUsernames.length) {
      utils.log(
        "warn",
        `Only found ${Object.keys(map).length} of ${
          targetUsernames.length
        } requested users.`
      );
    }

    return map;
  } catch (error) {
    utils.log("error", `Error fetching user map: ${error.message}`);
    throw error;
  }
}

/**
 * Fetches login days for specified users from LoginHistory
 * @param {Object} headers - HTTP headers with auth token
 * @param {Array<string>} userIds - Array of user IDs
 * @param {string} instance_url - Salesforce instance URL
 * @returns {Promise<Array<string>>} Array of login day strings (YYYY-MM-DD)
 */
async function fetchUserLoginDays(headers, userIds, instance_url) {
  utils.log("info", "Fetching user login history...");

  try {
    // Query LoginHistory object
    const formattedIds = userIds.map((id) => `'${id}'`).join(",");
    const query = `SELECT UserId, LoginTime FROM LoginHistory WHERE UserId IN (${formattedIds})`;

    const { data } = await axios.get(
      `${instance_url}/services/data/v57.0/query?q=${encodeURIComponent(
        query
      )}`,
      { headers }
    );

    // Extract unique dates from login times
    const uniqueDates = new Set(
      data.records.map((r) => r.LoginTime.split("T")[0])
    );
    const loginDays = [...uniqueDates].sort();

    utils.log(
      "info",
      `Found ${loginDays.length} login days from LoginHistory object`
    );
    return loginDays;
  } catch (error) {
    utils.log("error", `Error fetching login days: ${error.message}`);

    // Fallback: Use recent dates
    utils.log(
      "warn",
      "Could not access login history. Using fallback approach with recent dates."
    );

    // Use last 30 days
    const dates = [];
    const today = new Date();

    for (let i = 0; i < 30; i++) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      dates.push(date.toISOString().split("T")[0]);
    }

    utils.log("info", `Using fallback with ${dates.length} recent days`);
    return dates;
  }
}

module.exports = {
  loadTargetUsers,
  fetchUserMap,
  fetchUserLoginDays,
};
