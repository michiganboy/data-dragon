/**
 * Log processor for Salesforce event logs
 * Filters logs based on user activity and performs risk detection
 */
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const csvParser = require("csv-parser");
const config = require("../config/config");
const utils = require("../lib/utils");

class LogProcessor {
  /**
   * Creates a new LogProcessor instance
   * @param {Object} userMap - Map of userId -> username
   * @param {Object} riskDetection - Risk detection functions 
   */
  constructor(userMap, riskDetection) {
    this.userMap = userMap;
    this.riskDetection = riskDetection;
    this.allScannedFiles = [];
  }

  /**
   * Processes a Salesforce event log file
   * @param {Object} log - Log metadata
   * @param {Object} tokens - Authentication tokens
   * @param {string} logDate - Date of the log
   * @param {Object} headers - HTTP headers
   * @returns {Promise<Array>} Array of user IDs found in log
   */
  async processLog(log, tokens, logDate, headers) {
    const { EventType, LogFile } = log;
    const logFileName = `${EventType}_${logDate}.csv`;
    const logUrl = LogFile.startsWith("http")
      ? LogFile
      : `${tokens.instance_url}${LogFile}`;

    utils.log("info", `Processing log: ${EventType} - ${logDate}`);
    this.allScannedFiles.push({ EventType, logDate });

    try {
      const response = await axios.get(logUrl, {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
        },
        responseType: "stream",
      });

      return new Promise((resolve, reject) => {
        const filteredRows = [];
        const usersFound = new Set(); // Track which users were found in this log

        response.data
          .pipe(csvParser())
          .on("data", (row) => {
            // Only process rows for monitored users
            if (this.userMap[row.USER_ID_DERIVED]) {
              filteredRows.push(row);
              usersFound.add(row.USER_ID_DERIVED);
              this.riskDetection.checkForRisks(row, EventType);
            }
          })
          .on("end", () => {
            if (filteredRows.length > 0) {
              this.saveFilteredLog(logFileName, filteredRows);
              utils.log(
                "info",
                `Found ${filteredRows.length} matching entries in ${EventType} log`
              );
            } else {
              utils.log("info", `No matching entries in ${EventType} log`);
            }
            // Return the list of users found in this log
            resolve(Array.from(usersFound));
          })
          .on("error", (err) => {
            utils.log(
              "error",
              `Error processing ${EventType} log: ${err.message}`
            );
            reject(err);
          });
      });
    } catch (error) {
      utils.log(
        "error",
        `Failed to download ${EventType} log: ${error.message}`
      );
      // Continue processing other logs even if one fails
      return [];
    }
  }

  /**
   * Saves filtered log data to disk as CSV
   * @param {string} fileName - Name of the file to save
   * @param {Array} rows - Log data rows to save
   */
  saveFilteredLog(fileName, rows) {
    if (rows.length === 0) return;

    try {
      const filePath = path.join(config.EVENT_LOG_DIR, fileName);
      const stream = fs.createWriteStream(filePath);

      // Write headers
      stream.write(Object.keys(rows[0]).join(",") + "\n");

      // Write data rows
      rows.forEach((row) => {
        // Properly escape and quote values for CSV
        const values = Object.values(row).map((val) => {
          if (val === null || val === undefined) return "";
          // Quote strings with commas
          if (typeof val === "string" && val.includes(",")) {
            return `"${val.replace(/"/g, '""')}"`;
          }
          return val;
        });

        stream.write(values.join(",") + "\n");
      });

      stream.end();
    } catch (error) {
      utils.log(
        "error",
        `Error saving filtered log ${fileName}: ${error.message}`
      );
    }
  }

  /**
   * Gets all scanned log files
   * @returns {Array} Array of scanned files with EventType and logDate
   */
  getScannedFiles() {
    return this.allScannedFiles;
  }
}

module.exports = LogProcessor;
