// Risk detection configuration
const fs = require("fs");
const chalk = require("chalk");

// Helper function for time-based detection
function detectRapidAccess(
  row,
  eventType,
  session_key_field = "SESSION_KEY",
  user_id_field = "USER_ID_DERIVED",
  minTimeBetweenSecs = 2,
  requiredCount = 10
) {
  // Initialize global tracking if it doesn't exist
  if (!global.rapidAccessTracking) {
    global.rapidAccessTracking = new Map();
  }

  // Get the user and session keys
  const userId = row[user_id_field] || row.USER_ID;
  const sessionKey = row[session_key_field] || "unknown-session";
  const trackingKey = `${userId}-${sessionKey}-${eventType}`;

  // Initialize tracking for this user-session-event combination
  if (!global.rapidAccessTracking.has(trackingKey)) {
    global.rapidAccessTracking.set(trackingKey, {
      lastAccessTime: null,
      accessTimes: [],
      rapidAccessCount: 0,
      totalAccesses: 0,
    });
  }

  const tracking = global.rapidAccessTracking.get(trackingKey);
  tracking.totalAccesses++;

  // Parse the current timestamp - only use TIMESTAMP_DERIVED field
  const currentTime = new Date(row.TIMESTAMP_DERIVED);

  // Check if this is rapid access compared to previous
  if (tracking.lastAccessTime) {
    const timeDiffMs = currentTime - tracking.lastAccessTime;
    const timeDiffSec = timeDiffMs / 1000;

    // If events occur less than minTimeBetweenSecs apart, count as rapid access
    if (timeDiffSec < minTimeBetweenSecs) {
      tracking.rapidAccessCount++;
      tracking.accessTimes.push(timeDiffSec);

      // If we've exceeded the required count of rapid accesses, report the detection
      if (tracking.rapidAccessCount >= requiredCount) {
        const avgTimeBetweenAccess =
          tracking.accessTimes.reduce((sum, time) => sum + time, 0) /
          tracking.accessTimes.length;

        return {
          customMessage: `Rapid ${eventType} activity detected: ${
            tracking.rapidAccessCount
          } actions in quick succession (avg ${avgTimeBetweenAccess.toFixed(
            1
          )}s between actions)`,
          severityMultiplier: 2.0, // Higher severity for rapid access
          details: {
            rapidAccessCount: tracking.rapidAccessCount,
            totalAccesses: tracking.totalAccesses,
            averageTimeBetween: avgTimeBetweenAccess.toFixed(1),
          },
        };
      }
    }
  }

  // Update the last access time
  tracking.lastAccessTime = currentTime;

  return null;
}

// Advanced risk detection configuration - enhanced and expanded
const riskConfig = {
  ReportExport: {
    description: "Report Export Detected",
    threshold: 3, // Every instance is tracked
    severity: "high",
    rationale: "Direct path to data exfiltration",
    countField: null,
    // Advanced detection based on row values
    customDetection: (row) => {
      // Check if sensitive fields were exported
      if (row.RECORDS_PROCESSED && parseInt(row.RECORDS_PROCESSED) > 1000) {
        return {
          customMessage: `Large report export with ${row.RECORDS_PROCESSED} records`,
          severityMultiplier: 2,
        };
      }
      return null;
    },
  },
  DocumentAttachmentDownloads: {
    description: "Excessive Attachment Downloads",
    threshold: 20,
    severity: "high",
    rationale: "Bulk downloading indicates potential data theft",
    countField: null,
    timeWindow: "day", // Count per day
    customDetection: (row) => {
      // Additional check for sensitive document types
      const sensitiveTypes = ["pdf", "xlsx", "docx", "csv"];
      if (
        row.FILE_TYPE &&
        sensitiveTypes.some((type) =>
          row.FILE_TYPE.toLowerCase().includes(type)
        )
      ) {
        return {
          customMessage: `Sensitive file type download: ${row.FILE_TYPE}`,
          severityMultiplier: 1.5,
        };
      }
      return null;
    },
  },
  ContentDocumentLink: {
    description: "Excessive Internal Sharing",
    threshold: 20,
    severity: "medium",
    rationale:
      "Excessive internal sharing may indicate staging for exfiltration",
    countField: "RELATED_RECORD_ID", // Count unique documents shared
    timeWindow: "day",
    customDetection: (row) => {
      // Initialize tracking if it doesn't exist
      if (!global.contentSharingTracking) {
        global.contentSharingTracking = new Map();
      }

      // Track sharing by user-date
      const userId = row.USER_ID_DERIVED || row.USER_ID;
      const dateStr =
        row.EVENT_DATE ||
        new Date(row.TIMESTAMP_DERIVED).toISOString().split("T")[0];
      const trackingKey = `${userId}-${dateStr}`;

      if (!global.contentSharingTracking.has(trackingKey)) {
        global.contentSharingTracking.set(trackingKey, {
          sharedEntities: new Set(),
          sharedDocuments: new Set(),
          sharedDetails: [],
        });
      }

      const tracking = global.contentSharingTracking.get(trackingKey);

      // Add to tracking
      if (row.SHARED_WITH_ENTITY_ID) {
        tracking.sharedEntities.add(row.SHARED_WITH_ENTITY_ID);
      }

      if (row.RELATED_RECORD_ID) {
        tracking.sharedDocuments.add(row.RELATED_RECORD_ID);
      }

      // Add detailed mapping
      tracking.sharedDetails.push({
        document: row.RELATED_RECORD_ID || "Unknown Document",
        entity: row.SHARED_WITH_ENTITY_ID || "Unknown Entity",
        timestamp: row.TIMESTAMP_DERIVED,
      });

      // If we've exceeded threshold and have entity info
      if (
        tracking.sharedDocuments.size >= 20 &&
        tracking.sharedEntities.size > 0
      ) {
        // Format a readable sharing summary
        const uniqueEntities = Array.from(tracking.sharedEntities);
        const uniqueDocs = Array.from(tracking.sharedDocuments);

        // Create a summary of sharing activity
        const sharingList = tracking.sharedDetails
          .map((detail) => `${detail.document} → ${detail.entity}`)
          .join("; ");

        return {
          customMessage: `${uniqueDocs.length} documents shared with ${uniqueEntities.length} entities`,
          severityMultiplier: 1.0,
          additionalContext: {
            totalDocumentsShared: uniqueDocs.length,
            totalEntitiesSharedWith: uniqueEntities.length,
            sharingDetails: sharingList,
          },
        };
      }
      return null;
    },
  },
  ContentDistribution: {
    description: "Public Sharing Activity",
    threshold: 10,
    severity: "critical",
    rationale: "Public shares pose significant data exposure risk",
    countField: null,
    timeWindow: "day",
    customDetection: (row) => {
      // Check if publicly shared with password
      if (row.PASSWORD_PROTECTED === "false") {
        return {
          customMessage: "Public share without password protection",
          severityMultiplier: 2,
        };
      }
      return null;
    },
  },
  Login: {
    description: "Multiple IP Logins",
    threshold: 5,
    severity: "high",
    rationale: "Could indicate compromised credentials",
    countField: "CLIENT_IP",
    timeWindow: "day",
    customDetection: (row) => {
      // Check for suspicious IP geo transitions
      if (
        row.PREV_LOGIN_IP &&
        row.CLIENT_IP &&
        row.PREV_LOGIN_IP !== row.CLIENT_IP
      ) {
        // Calculate time since previous login (if available)
        if (row.PREV_LOGIN_TIME && row.LOGIN_TIME) {
          const prevTime = new Date(row.PREV_LOGIN_TIME);
          const currTime = new Date(row.LOGIN_TIME);
          const hoursDiff = (currTime - prevTime) / (1000 * 60 * 60);

          // If less than 1 hour between logins from different IPs, flag as suspicious
          if (hoursDiff < 1) {
            return {
              customMessage: `Suspicious rapid IP change: ${
                row.PREV_LOGIN_IP
              } → ${row.CLIENT_IP} in ${hoursDiff.toFixed(2)} hours`,
              severityMultiplier: 3,
            };
          }
        }
        return {
          customMessage: `IP change: ${row.PREV_LOGIN_IP} → ${row.CLIENT_IP}`,
          severityMultiplier: 1.5,
        };
      }
      return null;
    },
  },
  LoginAs: {
    description: "Admin Impersonation",
    threshold: 3,
    severity: "high",
    rationale: "Admin impersonation always warrants review",
    countField: null,
    customDetection: (row) => {
      // Track which admin performed the login-as
      if (row.DELEGATED_USERNAME) {
        return {
          customMessage: `Impersonated by admin: ${row.DELEGATED_USERNAME}`,
          severityMultiplier: 1,
        };
      }
      return null;
    },
  },
  Sites: {
    description: "Internal Access via Guest User",
    threshold: 3,
    severity: "high",
    rationale: "May indicate misuse of public access",
    countField: null,
    customDetection: (row) => {
      // Check for specific actions that are higher risk
      const sensitiveActions = ["create", "update", "delete"];
      if (
        row.ACTION &&
        sensitiveActions.some((action) =>
          row.ACTION.toLowerCase().includes(action)
        )
      ) {
        return {
          customMessage: `Guest user performed ${row.ACTION} operation`,
          severityMultiplier: 2,
        };
      }
      return null;
    },
  },
  Search: {
    description: "Excessive Search Activity",
    threshold: 100,
    severity: "medium",
    rationale: "Bulk recon activity",
    countField: null,
    timeWindow: "session",
    customDetection: (row) => {
      // Check for wildcard searches which may indicate scraping
      if (
        row.QUERY_STRING &&
        (row.QUERY_STRING.includes("*") || row.QUERY_STRING === "%")
      ) {
        return {
          customMessage: "Wildcard search pattern detected",
          severityMultiplier: 1.5,
        };
      }

      // Time-based detection for rapid search activity
      const rapidAccessDetection = detectRapidAccess(
        row,
        "Search",
        "SESSION_KEY",
        "USER_ID_DERIVED",
        3,
        15
      );
      if (rapidAccessDetection) {
        return rapidAccessDetection;
      }

      return null;
    },
  },
  ApexCallout: {
    description: "High Volume External Callouts",
    threshold: 30,
    severity: "high",
    rationale: "May indicate external data exfiltration",
    countField: "ENDPOINT_URL", // Track unique endpoints
    timeWindow: "hour",
    customDetection: (row) => {
      // Check for unofficial/unexpected endpoints
      const allowedDomains = ["api.salesforce.com", "yourcompany.com"];
      if (row.ENDPOINT_URL) {
        const isAllowedDomain = allowedDomains.some((domain) =>
          row.ENDPOINT_URL.includes(domain)
        );
        if (!isAllowedDomain) {
          return {
            customMessage: `Callout to non-approved endpoint: ${row.ENDPOINT_URL}`,
            severityMultiplier: 2,
          };
        }
      }
      return null;
    },
  },
  VisualforceRequest: {
    description: "Possible Page Scraping",
    threshold: 75,
    severity: "medium",
    rationale: "Possible scraping or automation",
    countField: "PAGE_NAME",
    timeWindow: "session",
    customDetection: (row) => {
      // Time-based detection for rapid page access
      const rapidAccessDetection = detectRapidAccess(
        row,
        "Visualforce Page",
        "SESSION_KEY",
        "USER_ID_DERIVED",
        0.5,
        20
      );
      if (rapidAccessDetection) {
        return rapidAccessDetection;
      }

      // Look for rapid page loads or sensitive pages
      if (row.PAGE_NAME && row.PAGE_NAME.toLowerCase().includes("admin")) {
        return {
          customMessage: `Admin Visualforce page accessed: ${row.PAGE_NAME}`,
          severityMultiplier: 1.5,
        };
      }
      return null;
    },
  },
  AuraRequest: {
    description: "Excessive Component Loading",
    threshold: 75,
    severity: "medium",
    rationale: "Possible scraping or automation (Lightning specific)",
    countField: "COMPONENT_NAME",
    timeWindow: "session",
    customDetection: (row) => {
      // Time-based detection for rapid component loading
      const rapidAccessDetection = detectRapidAccess(
        row,
        "Lightning Component",
        "SESSION_KEY",
        "USER_ID_DERIVED",
        0.5,
        25
      );
      if (rapidAccessDetection) {
        return rapidAccessDetection;
      }

      return null;
    },
  },
  LightningPageView: {
    description: "Unusual Page View Volume",
    threshold: 100,
    severity: "medium",
    rationale: "Recon or bulk record viewing",
    countField: "PAGE_ENTITY_TYPE",
    timeWindow: "session",
    customDetection: (row) => {
      // Time-based detection for rapid page views
      const rapidAccessDetection = detectRapidAccess(
        row,
        "Lightning Page",
        "SESSION_KEY",
        "USER_ID_DERIVED",
        0.5,
        25
      );
      if (rapidAccessDetection) {
        return rapidAccessDetection;
      }

      return null;
    },
  },
  Dashboard: {
    description: "Multiple Dashboard Access",
    threshold: 15,
    severity: "medium",
    rationale: "Unusual recon or data collection",
    countField: "DASHBOARD_ID",
    timeWindow: "day",
    customDetection: (row) => {
      // Time-based detection for rapid dashboard access
      const rapidAccessDetection = detectRapidAccess(
        row,
        "Dashboard",
        "SESSION_KEY",
        "USER_ID_DERIVED",
        5,
        10
      );
      if (rapidAccessDetection) {
        return rapidAccessDetection;
      }

      return null;
    },
  },
  AsyncReportRun: {
    description: "Background Reports",
    threshold: 15,
    severity: "high",
    rationale: "Data staging for later extraction",
    countField: null,
    timeWindow: "day",
  },
  FlowExecution: {
    description: "Manual Flow Trigger",
    threshold: 3,
    severity: "high",
    rationale: "Direct process manipulation",
    countField: "FLOW_NAME",
    customDetection: (row) => {
      // Check if the flow is administrative or high-privilege
      const sensitiveFlowPatterns = [
        "admin",
        "delete",
        "purge",
        "mass",
        "bulk",
      ];
      if (
        row.FLOW_NAME &&
        sensitiveFlowPatterns.some((pattern) =>
          row.FLOW_NAME.toLowerCase().includes(pattern)
        )
      ) {
        return {
          customMessage: `Sensitive flow executed: ${row.FLOW_NAME}`,
          severityMultiplier: 2,
        };
      }
      return null;
    },
  },
  ApexExecution: {
    description: "Direct Apex Execution",
    threshold: 3,
    severity: "critical",
    rationale: "Possible direct manipulation or abuse",
    countField: "APEX_CLASS_NAME",
    customDetection: (row) => {
      // Higher severity for direct data manipulation
      const criticalClasses = ["data", "admin", "user", "security"];
      if (
        row.APEX_CLASS_NAME &&
        criticalClasses.some((cls) =>
          row.APEX_CLASS_NAME.toLowerCase().includes(cls)
        )
      ) {
        return {
          customMessage: `Critical Apex class executed: ${row.APEX_CLASS_NAME}`,
          severityMultiplier: 3,
        };
      }
      return null;
    },
  },
  ApexTriggerExecution: {
    description: "Apex Trigger Spike",
    threshold: 150,
    severity: "medium",
    rationale: "Unusual mass-trigger events",
    countField: "TRIGGER_NAME",
    timeWindow: "day",
  },
  // New expanded risk types
  ApiAnomalyEventStore: {
    description: "API Anomaly Detected",
    threshold: 3,
    severity: "critical",
    rationale: "Salesforce detected platform anomaly",
    countField: null,
    customDetection: (row) => {
      // Salesforce's own detection is already flagging this
      return {
        customMessage: `API anomaly: ${row.SCORE || "Unknown"} score | ${
          row.EVENT_TYPE || "Unknown type"
        }`,
        severityMultiplier: 3,
      };
    },
  },
  BulkApiRequest: {
    description: "Bulk API Usage",
    threshold: 10,
    severity: "medium",
    rationale: "Mass data operations through API",
    countField: "OPERATION_TYPE",
    timeWindow: "day",
    customDetection: (row) => {
      // Check operations and record volumes
      if (row.RECORDS_PROCESSED && parseInt(row.RECORDS_PROCESSED) > 10000) {
        return {
          customMessage: `Large bulk operation with ${row.RECORDS_PROCESSED} records`,
          severityMultiplier: 2,
        };
      }
      return null;
    },
  },
  PermissionSetAssignment: {
    description: "Permission Changes",
    threshold: 3,
    severity: "high",
    rationale: "Permission changes could indicate privilege escalation",
    countField: null,
    customDetection: (row) => {
      // Track specific permission sets of interest
      const sensitiveSets = ["admin", "manage", "delete", "all"];
      if (
        row.PERMISSION_SET_NAME &&
        sensitiveSets.some((set) =>
          row.PERMISSION_SET_NAME.toLowerCase().includes(set)
        )
      ) {
        return {
          customMessage: `High privilege permission set assigned: ${row.PERMISSION_SET_NAME}`,
          severityMultiplier: 2.5,
        };
      }
      return null;
    },
  },
  LightningError: {
    description: "Unusual Error Rate",
    threshold: 30,
    severity: "medium",
    rationale: "High error rates may indicate attempted exploitation",
    countField: "ERROR_TYPE",
    timeWindow: "hour",
  },
  LogoutEvent: {
    description: "Unusual Logout Pattern",
    threshold: 15,
    severity: "low",
    rationale: "Excessive login/logout cycles may indicate session harvesting",
    countField: null,
    timeWindow: "day",
  },
  DataExport: {
    description: "Organization Data Export",
    threshold: 3,
    severity: "critical",
    rationale: "Complete org data extraction",
    countField: null,
  },
};

// Load custom risk configuration from file
function loadCustomConfig(configPath) {
  try {
    if (fs.existsSync(configPath)) {
      const customConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));

      // Merge with existing config
      Object.entries(customConfig).forEach(([eventType, config]) => {
        if (riskConfig[eventType]) {
          // Only override properties that exist in custom config
          Object.entries(config).forEach(([key, value]) => {
            if (key !== "customDetection") {
              // Don't override functions
              riskConfig[eventType][key] = value;
            }
          });

          console.log(
            chalk.yellow(`[INFO] Custom config loaded for ${eventType}`)
          );
        }
      });
    } else {
      console.log(
        chalk.yellow(`[INFO] Custom config file not found: ${configPath}`)
      );
    }
  } catch (error) {
    console.error(
      chalk.red(`[ERROR] Error loading custom config: ${error.message}`)
    );
  }
}

// Helper function to sanitize config for output (remove functions)
function sanitizeConfigForOutput(config) {
  const sanitized = {};
  Object.entries(config).forEach(([key, value]) => {
    sanitized[key] = { ...value };
    delete sanitized[key].customDetection;
  });
  return sanitized;
}

module.exports = {
  riskConfig,
  loadCustomConfig,
  sanitizeConfigForOutput,
};
