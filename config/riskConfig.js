// Risk detection configuration
const fs = require("fs");
const chalk = require("chalk");

const riskConfig = {
  ReportExport: {
    description: "Report Export",
    threshold: 1,
    severity: "critical",
    rationale: "Every report export is a potential data exfiltration risk",
    countField: "REPORT_ID",
    timeWindow: "day",
  },
  DocumentAttachmentDownloads: {
    description: "Document Download",
    threshold: 1,
    severity: "critical",
    rationale: "Every document download is a potential data exfiltration risk",
    countField: "DOCUMENT_ID",
    timeWindow: "hour",
    customDetection: (row) => {
      // Only proceed if we have the required fields
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      
      // Get the hour of the day (0-23)
      const hour = currentTime.getHours();
      
      // Create a tracking key for this user-hour combination
      const trackingKey = `${userId}-${hour}`;

      // Initialize tracking if it doesn't exist
      if (!global.documentDownloadTracking) {
        global.documentDownloadTracking = new Map();
      }

      // Initialize tracking for this user-hour combination
      if (!global.documentDownloadTracking.has(trackingKey)) {
        global.documentDownloadTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime
        });
      }

      const tracking = global.documentDownloadTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      // Alert on every download
      return {
        customMessage: `Document download detected for user ${userId} during hour ${hour}: ${row.DOCUMENT_ID || 'Unknown document'}`,
        severityMultiplier: 2.0
      };
    }
  },
  ContentDocumentLink: {
    description: "Excessive Internal Sharing",
    threshold: 20,
    severity: "medium",
    rationale: "Excessive internal sharing may indicate staging for exfiltration",
    countField: "RELATED_RECORD_ID",
    timeWindow: "day",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}`;

      if (!global.contentSharingTracking) {
        global.contentSharingTracking = new Map();
      }

      if (!global.contentSharingTracking.has(trackingKey)) {
        global.contentSharingTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false
        });
      }

      const tracking = global.contentSharingTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      // Don't alert until we have at least the minimum threshold of events
      if (tracking.count < 20) {
        return null;
      }

      // Calculate time window in milliseconds
      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      
      // If time window is less than 1 second, don't alert (avoid division by zero)
      if (timeWindowMs < 1000) {
        return null;
      }

      let timeDisplay;
      let rateDisplay;
      
      if (timeWindowMs < 60000) { // Less than a minute
        const seconds = Math.max(1, Math.round(timeWindowMs / 1000));
        const sharesPerSecond = tracking.count / seconds;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(sharesPerSecond * 100) / 100} shares/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        const sharesPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(sharesPerMinute * 100) / 100} shares/min`;
      }

      if (!tracking.alerted) {
        tracking.alerted = true;
        return {
          customMessage: `High content sharing rate detected for user ${userId} during hour ${hour}: ${tracking.count} shares in ${timeDisplay} (${rateDisplay})`,
          severityMultiplier: 1.5
        };
      }

      return null;
    }
  },
  ContentDistribution: {
    description: "Public Sharing Activity",
    threshold: 5,
    severity: "critical",
    rationale: "Significant data exposure risk",
    countField: "CONTENT_ID",
    timeWindow: "day",
  },
  Login: {
    description: "Multiple IP Logins",
    threshold: 3,
    severity: "high",
    rationale: "Could indicate compromised credentials",
    countField: "SOURCE_IP",
    timeWindow: "day",
  },
  LoginAs: {
    description: "Admin Impersonation",
    threshold: 1,
    severity: "high",
    rationale: "Admin impersonation warrants review",
    countField: null,
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
    severity: "high",
    rationale: "Bulk recon activity",
    countField: null,
    timeWindow: "hour",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}`;

      if (!global.searchTracking) {
        global.searchTracking = new Map();
      }

      if (!global.searchTracking.has(trackingKey)) {
        global.searchTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false
        });
      }

      const tracking = global.searchTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      // Don't alert until we have at least the minimum threshold of events
      if (tracking.count < 100) {
        return null;
      }

      // Calculate time window in milliseconds
      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      
      // If time window is less than 1 second, don't alert (avoid division by zero)
      if (timeWindowMs < 1000) {
        return null;
      }

      let timeDisplay;
      let rateDisplay;
      
      if (timeWindowMs < 60000) { // Less than a minute
        const seconds = Math.max(1, Math.round(timeWindowMs / 1000));
        const searchesPerSecond = tracking.count / seconds;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(searchesPerSecond * 100) / 100} searches/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        const searchesPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(searchesPerMinute * 100) / 100} searches/min`;
      }

      if (!tracking.alerted) {
        tracking.alerted = true;
        return {
          customMessage: `High search rate detected for user ${userId} during hour ${hour}: ${tracking.count} searches in ${timeDisplay} (${rateDisplay})`,
          severityMultiplier: 1.5
        };
      }

      return null;
    }
  },
  ApexCallout: {
    description: "High Volume External Callouts",
    threshold: 30,
    severity: "high",
    rationale: "May indicate external data exfiltration",
    countField: "ENDPOINT_URL",
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
    threshold: 100,
    severity: "high",
    rationale: "Possible scraping or automation",
    countField: "PAGE_NAME",
    timeWindow: "hour",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}`;

      if (!global.visualforceTracking) {
        global.visualforceTracking = new Map();
      }

      if (!global.visualforceTracking.has(trackingKey)) {
        global.visualforceTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false
        });
      }

      const tracking = global.visualforceTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      // Don't alert until we have at least the minimum threshold of events
      if (tracking.count < 100) {
        return null;
      }

      // Calculate time window in milliseconds
      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      
      // If time window is less than 1 second, don't alert (avoid division by zero)
      if (timeWindowMs < 1000) {
        return null;
      }

      let timeDisplay;
      let rateDisplay;
      
      if (timeWindowMs < 60000) { // Less than a minute
        const seconds = Math.max(1, Math.round(timeWindowMs / 1000));
        const requestsPerSecond = tracking.count / seconds;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(requestsPerSecond * 100) / 100} requests/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        const requestsPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(requestsPerMinute * 100) / 100} requests/min`;
      }

      if (!tracking.alerted) {
        tracking.alerted = true;
        return {
          customMessage: `High Visualforce request rate detected for user ${userId} during hour ${hour}: ${tracking.count} requests in ${timeDisplay} (${rateDisplay})`,
          severityMultiplier: 1.5
        };
      }

      return null;
    }
  },
  AuraRequest: {
    description: "Excessive Component Loading",
    threshold: 800,
    severity: "high",
    rationale: "Possible scraping or automation (Lightning specific)",
    countField: "COMPONENT_NAME",
    timeWindow: "hour",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}`;

      if (!global.auraRequestTracking) {
        global.auraRequestTracking = new Map();
      }

      if (!global.auraRequestTracking.has(trackingKey)) {
        global.auraRequestTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false
        });
      }

      const tracking = global.auraRequestTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      // Don't alert until we have at least the minimum threshold of events
      if (tracking.count < 800) {
        return null;
      }

      // Calculate time window in milliseconds
      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      
      // If time window is less than 1 second, don't alert (avoid division by zero)
      if (timeWindowMs < 1000) {
        return null;
      }

      let timeDisplay;
      let rateDisplay;
      
      if (timeWindowMs < 60000) { // Less than a minute
        const seconds = Math.max(1, Math.round(timeWindowMs / 1000));
        const requestsPerSecond = tracking.count / seconds;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(requestsPerSecond * 100) / 100} requests/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        const requestsPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(requestsPerMinute * 100) / 100} requests/min`;
      }

      if (!tracking.alerted) {
        tracking.alerted = true;
        return {
          customMessage: `High AuraRequest rate detected for user ${userId} during hour ${hour}: ${tracking.count} requests in ${timeDisplay} (${rateDisplay})`,
          severityMultiplier: 1.5
        };
      }

      return null;
    }
  },
  LightningPageView: {
    description: "Unusual Page View Volume",
    threshold: 200,
    severity: "high",
    rationale: "Recon or bulk record viewing",
    countField: "PAGE_ENTITY_TYPE",
    timeWindow: "hour",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}`;

      if (!global.lightningPageViewTracking) {
        global.lightningPageViewTracking = new Map();
      }

      if (!global.lightningPageViewTracking.has(trackingKey)) {
        global.lightningPageViewTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false
        });
      }

      const tracking = global.lightningPageViewTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      // Don't alert until we have at least the minimum threshold of events
      if (tracking.count < 200) {
        return null;
      }

      // Calculate time window in milliseconds
      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      
      // If time window is less than 1 second, don't alert (avoid division by zero)
      if (timeWindowMs < 1000) {
        return null;
      }

      let timeDisplay;
      let rateDisplay;
      
      if (timeWindowMs < 60000) { // Less than a minute
        const seconds = Math.max(1, Math.round(timeWindowMs / 1000));
        const viewsPerSecond = tracking.count / seconds;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(viewsPerSecond * 100) / 100} views/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        const viewsPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(viewsPerMinute * 100) / 100} views/min`;
      }

      if (!tracking.alerted) {
        tracking.alerted = true;
        return {
          customMessage: `High Lightning page view rate detected for user ${userId} during hour ${hour}: ${tracking.count} views in ${timeDisplay} (${rateDisplay})`,
          severityMultiplier: 1.5
        };
      }

      return null;
    }
  },
  Dashboard: {
    description: "Multiple Dashboard Access",
    threshold: 100,
    severity: "medium",
    rationale: "Unusual recon or data collection",
    countField: null,
    timeWindow: "hour",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) {
        return null;
      }

      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}`;

      if (!global.dashboardTracking) {
        global.dashboardTracking = new Map();
      }

      if (!global.dashboardTracking.has(trackingKey)) {
        global.dashboardTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false,
          uniqueDashboards: new Set() 
        });
      }

      const tracking = global.dashboardTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;
      
      // Track unique dashboards for reporting
      if (row.DASHBOARD_ID) {
        tracking.uniqueDashboards.add(row.DASHBOARD_ID);
      }

      // Early return if count threshold not met
      if (tracking.count < 100) {
        return null;
      }

      // Calculate time window in milliseconds
      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      
      // Ensure we have a reasonable time window to calculate rates
      if (timeWindowMs < 5000) {
        return null;
      }

      let timeDisplay;
      let rateDisplay;
      let requestsPerMinute = 0;
      
      if (timeWindowMs < 60000) {
        const seconds = Math.max(5, Math.round(timeWindowMs / 1000));
        const requestsPerSecond = tracking.count / seconds;
        requestsPerMinute = requestsPerSecond * 60;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(requestsPerSecond * 100) / 100} requests/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        requestsPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(requestsPerMinute * 100) / 100} requests/min`;
      }

      const MIN_RATE_THRESHOLD = 20;
      
      if (tracking.count >= 100 && requestsPerMinute >= MIN_RATE_THRESHOLD && !tracking.alerted) {
        tracking.alerted = true;
        return {
          customMessage: `High Dashboard access rate detected for user ${userId} during hour ${hour}: ${tracking.count} requests in ${timeDisplay} (${rateDisplay}) across ${tracking.uniqueDashboards.size} unique dashboards`,
          severityMultiplier: 1.5
        };
      }

      return null;
    }
  },
  AsyncReportRun: {
    description: "Background Report Execution",
    threshold: 1,
    severity: "critical",
    rationale: "Every background report execution is a potential data staging risk",
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
    countField: "QUIDDITY",
    customDetection: (row) => {
      if (!row.USER_ID_DERIVED || !row.TIMESTAMP_DERIVED) return null;

      const quiddity = row.QUIDDITY || '';
      const entryPoint = row.ENTRY_POINT || '';
      
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

      // Only these types are considered high risk
      const highRiskTypes = ['A', 'X', 'W'];
      
      // Skip low-risk types that are likely just normal page functionality
      // Only alert on high-risk execution types
      if (!highRiskTypes.includes(quiddity)) {
        return null;
      }
      
      const userId = row.USER_ID_DERIVED;
      const currentTime = new Date(row.TIMESTAMP_DERIVED);
      const hour = currentTime.getHours();
      const trackingKey = `${userId}-${hour}-${quiddity}`;

      if (!global.apexExecutionTracking) {
        global.apexExecutionTracking = new Map();
      }

      if (!global.apexExecutionTracking.has(trackingKey)) {
        global.apexExecutionTracking.set(trackingKey, {
          count: 0,
          firstAccess: currentTime,
          lastAccess: currentTime,
          alerted: false
        });
      }

      const tracking = global.apexExecutionTracking.get(trackingKey);
      tracking.count++;
      tracking.lastAccess = currentTime;

      if (tracking.count < 3) return null;

      const timeWindowMs = tracking.lastAccess - tracking.firstAccess;
      if (timeWindowMs < 1000) return null;

      let timeDisplay;
      let rateDisplay;
      
      if (timeWindowMs < 60000) {
        const seconds = Math.max(1, Math.round(timeWindowMs / 1000));
        const executionsPerSecond = tracking.count / seconds;
        timeDisplay = `${seconds} second${seconds !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(executionsPerSecond * 100) / 100} executions/sec`;
      } else {
        const minutes = Math.max(1, Math.round(timeWindowMs / 60000));
        const executionsPerMinute = tracking.count / minutes;
        timeDisplay = `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        rateDisplay = `${Math.round(executionsPerMinute * 100) / 100} executions/min`;
      }

      if (!tracking.alerted) {
        tracking.alerted = true;
        const executionType = quiddityMap[quiddity] || 'Unknown Type';
        const contextInfo = entryPoint ? ` via ${entryPoint}` : '';
        const severityMultiplier = 3; // High severity for these high-risk types
        
        return {
          customMessage: `High rate of ${executionType} executions detected for user ${userId} during hour ${hour}${contextInfo}: ${tracking.count} executions in ${timeDisplay} (${rateDisplay})`,
          severityMultiplier
        };
      }

      return null;
    }
  },
  ApexTriggerExecution: {
    description: "Apex Trigger Spike",
    threshold: 150,
    severity: "medium",
    rationale: "Unusual mass-trigger events",
    countField: "TRIGGER_NAME",
    timeWindow: "day",
  },
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
    threshold: 1,
    severity: "critical",
    rationale: "Every org data export is a critical security event",
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
