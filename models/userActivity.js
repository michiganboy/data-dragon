// User Activity Model
// This module handles user activity data including login patterns and anomaly detection

const utils = require("../lib/utils");

/**
 * UserActivity class to store and analyze user login patterns and activity
 */
class UserActivity {
  /**
   * Create a new UserActivity instance
   * @param {string} userId - Salesforce User ID
   * @param {string} username - User's username/email
   */
  constructor(userId, username) {
    this.userId = userId;
    this.username = username;
    this.loginDays = [];
    this.loginTimes = [];
    this.ipAddresses = new Map(); // IP address -> frequency count
    this.knownLocations = new Set(); // Known locations based on IP
    this.warnings = []; // Security warnings related to this user
    this.lastAnalysisDate = null;
    this.riskScore = 0; // Cumulative risk score based on patterns
    this.riskFactors = []; // Factors that contributed to risk score
    this.anomalies = []; // Detected anomalies
    this.scannedLogs = new Map(); // EventType -> count of logs scanned
    this.criticalEvents = 0; // Count of critical events
    this.highRiskEvents = 0; // Count of high risk events
  }

  /**
   * Add login history data to the user activity record
   * @param {Object[]} loginRecords - Records from LoginHistory object
   */
  addLoginHistory(loginRecords) {
    if (!loginRecords || !Array.isArray(loginRecords)) return;

    loginRecords.forEach((record) => {
      // Extract date and time
      if (record.LoginTime) {
        const loginDate = new Date(record.LoginTime);
        const dateStr = loginDate.toISOString().split("T")[0];

        // Add to login days if not already present
        if (!this.loginDays.includes(dateStr)) {
          this.loginDays.push(dateStr);
        }

        // Add full login time for pattern analysis
        this.loginTimes.push({
          datetime: loginDate,
          dayOfWeek: loginDate.getDay(),
          hourOfDay: loginDate.getHours(),
          weekend: loginDate.getDay() === 0 || loginDate.getDay() === 6,
        });
      }

      // Track IP addresses
      if (record.SourceIp) {
        const currentCount = this.ipAddresses.get(record.SourceIp) || 0;
        this.ipAddresses.set(record.SourceIp, currentCount + 1);
      }

      // Track location if available
      if (record.LoginGeoId) {
        this.knownLocations.add(record.LoginGeoId);
      }
    });

    // Sort login days
    this.loginDays.sort();
  }

  /**
   * Add a warning to this user's activity record
   * @param {Object} warning - Warning object
   */
  addWarning(warning) {
    if (!warning) return;

    this.warnings.push({
      ...warning,
      timestamp: warning.timestamp || warning.date,
    });
  }

  /**
   * Record that a specific event log type was scanned for this user
   * @param {string} eventType - Type of event log
   */
  recordScannedLog(eventType) {
    if (!eventType) return;

    const currentCount = this.scannedLogs.get(eventType) || 0;
    this.scannedLogs.set(eventType, currentCount + 1);
  }

  /**
   * Analyze login patterns to detect anomalies
   * @returns {Object[]} Array of detected anomalies
   */
  analyzeLoginPatterns() {
    // Skip if not enough data
    if (this.loginTimes.length < 2) {
      return [];
    }

    const anomalies = [];

    // Analyze time patterns
    const timePatterns = this.detectTimePatterns();
    if (timePatterns.unusualHours.length > 0) {
      anomalies.push({
        type: "unusual_hours",
        severity: "medium",
        description: `Unusual login hours detected: ${timePatterns.unusualHours.join(
          ", "
        )}`,
        details: timePatterns.unusualHours,
      });
    }

    // Analyze IP address changes
    const ipAnomalies = this.detectRapidIPChanges();
    if (ipAnomalies.length > 0) {
      ipAnomalies.forEach((anomaly) => {
        anomalies.push({
          type: "rapid_ip_change",
          severity: "high",
          description: `Rapid IP change: ${anomaly.from} → ${anomaly.to} (${anomaly.hours} hours)`,
          details: anomaly,
        });
      });
    }

    // Analyze weekend activity if user normally doesn't work weekends
    const weekendAnomalies = this.detectWeekendAnomalies();
    if (weekendAnomalies.active && weekendAnomalies.unusual) {
      anomalies.push({
        type: "weekend_activity",
        severity: "low",
        description: "Unusual weekend activity detected",
        details: weekendAnomalies,
      });
    }

    // Store anomalies and update last analysis time
    this.anomalies = anomalies;
    this.lastAnalysisDate = new Date().toISOString();

    // Calculate overall risk score based on anomalies
    this.calculateRiskScore();

    return anomalies;
  }

  /**
   * Detect unusual login time patterns
   * @private
   * @returns {Object} Time pattern analysis results
   */
  detectTimePatterns() {
    // Count logins by hour of day
    const hourCounts = new Array(24).fill(0);
    this.loginTimes.forEach((login) => {
      hourCounts[login.hourOfDay]++;
    });

    // Find user's normal working hours (hours with higher than average login counts)
    const totalLogins = this.loginTimes.length;
    const avgLoginsPerHour = totalLogins / 24;
    const normalHours = [];
    const unusualHours = [];

    hourCounts.forEach((count, hour) => {
      if (count >= avgLoginsPerHour * 0.5) {
        normalHours.push(hour);
      }
    });

    // Check recent logins for unusual hours
    const recentLoginCutoff = new Date();
    recentLoginCutoff.setDate(recentLoginCutoff.getDate() - 7); // Last 7 days

    this.loginTimes
      .filter((login) => login.datetime >= recentLoginCutoff)
      .forEach((login) => {
        if (
          !normalHours.includes(login.hourOfDay) &&
          !unusualHours.includes(login.hourOfDay)
        ) {
          unusualHours.push(login.hourOfDay);
        }
      });

    return {
      normalHours: normalHours.sort((a, b) => a - b),
      unusualHours: unusualHours.sort((a, b) => a - b),
    };
  }

  /**
   * Detect suspicious rapid changes in IP addresses
   * @private
   * @returns {Object[]} Array of rapid IP change anomalies
   */
  detectRapidIPChanges() {
    const anomalies = [];
    const recentLogins = [...this.loginTimes];

    // Sort login times chronologically
    recentLogins.sort((a, b) => a.datetime - b.datetime);

    // Need at least 2 logins to detect changes
    if (recentLogins.length < 2) {
      return anomalies;
    }

    // Check for logins from different IPs within a short timeframe
    for (let i = 1; i < recentLogins.length; i++) {
      const prevLogin = recentLogins[i - 1];
      const currLogin = recentLogins[i];

      // If IP information isn't available, skip
      if (!prevLogin.sourceIp || !currLogin.sourceIp) continue;

      // Skip if same IP
      if (prevLogin.sourceIp === currLogin.sourceIp) continue;

      // Calculate hours between logins
      const hoursDiff =
        (currLogin.datetime - prevLogin.datetime) / (1000 * 60 * 60);

      // Flag as anomaly if less than 4 hours between logins from different IPs
      if (hoursDiff < 4) {
        anomalies.push({
          from: prevLogin.sourceIp,
          to: currLogin.sourceIp,
          hours: hoursDiff.toFixed(2),
          prevTime: prevLogin.datetime.toISOString(),
          currTime: currLogin.datetime.toISOString(),
        });
      }
    }

    return anomalies;
  }

  /**
   * Detect unusual weekend activity
   * @private
   * @returns {Object} Weekend activity analysis
   */
  detectWeekendAnomalies() {
    // Count weekend vs weekday logins
    let weekendLogins = 0;
    let weekdayLogins = 0;

    this.loginTimes.forEach((login) => {
      if (login.weekend) {
        weekendLogins++;
      } else {
        weekdayLogins++;
      }
    });

    // If user has significant login history
    if (this.loginTimes.length >= 10) {
      const weekendRatio = weekendLogins / this.loginTimes.length;

      // If user rarely logs in on weekends (<10% of logins)
      const rareWeekendUser = weekendRatio < 0.1;

      // Check for recent weekend activity in a user who rarely works weekends
      const recentLoginCutoff = new Date();
      recentLoginCutoff.setDate(recentLoginCutoff.getDate() - 7); // Last 7 days

      const recentWeekendActivity = this.loginTimes
        .filter((login) => login.datetime >= recentLoginCutoff)
        .some((login) => login.weekend);

      return {
        weekendLogins,
        weekdayLogins,
        weekendRatio,
        rareWeekendUser,
        recentWeekendActivity,
        active: recentWeekendActivity,
        unusual: rareWeekendUser,
      };
    }

    return {
      weekendLogins,
      weekdayLogins,
      active: false,
      unusual: false,
    };
  }

  /**
   * Calculate a risk score based on anomalies and warning patterns
   * with priority given to critical security events
   * @private
   */
  calculateRiskScore() {
    let score = 0;
    const riskFactors = []; // Track what contributed to the risk score
    let criticalEvents = 0;
    let highRiskEvents = 0;

    // Add points for each anomaly based on severity
    this.anomalies.forEach((anomaly) => {
      let points = 0;
      switch (anomaly.severity) {
        case "critical":
          points = 40;
          criticalEvents++;
          break;
        case "high":
          points = 25;
          highRiskEvents++;
          break;
        case "medium":
          points = 15;
          break;
        case "low":
          points = 5;
          break;
        default:
          points = 2;
      }

      score += points;
      riskFactors.push(`Anomaly - ${anomaly.type} (${points} points)`);
    });

    // Process security warnings with special handling for critical event types
    this.warnings.forEach((warning) => {
      let points = 0;
      let isHighPriorityEvent = false;

      // Check if this is a high-priority event that should automatically
      // trigger high or critical risk levels
      if (warning.eventType) {
        const eventType = warning.eventType.toLowerCase();

        // Direct data exfiltration events
        if (
          eventType === "reportexport" ||
          eventType === "dataexport" ||
          (eventType === "bulkapirequest" &&
            warning.context?.RECORDS_PROCESSED > 10000)
        ) {
          points = 150; // Immediate critical risk
          criticalEvents++;
          isHighPriorityEvent = true;
          score += points; // Add points to total score - FIXED
          riskFactors.push(
            `CRITICAL EVENT - ${warning.eventType}: ${warning.warning} (${points} points)`
          );
        }
        // Admin/system level events
        else if (
          eventType === "loginas" ||
          eventType === "apexexecution" ||
          eventType === "permissionsetassignment" ||
          eventType === "apianomaly"
        ) {
          points = 100; // Immediate high risk
          highRiskEvents++;
          isHighPriorityEvent = true;
          score += points; // Add points to total score - FIXED
          riskFactors.push(
            `HIGH PRIORITY EVENT - ${warning.eventType}: ${warning.warning} (${points} points)`
          );
        }
      }

      // If not a special high-priority event, use the standard severity-based scoring
      if (!isHighPriorityEvent) {
        switch (warning.severity) {
          case "critical":
            points = 50;
            criticalEvents++;
            break;
          case "high":
            points = 30;
            highRiskEvents++;
            break;
          case "medium":
            points = 15;
            break;
          case "low":
            points = 5;
            break;
          default:
            points = 2;
        }

        score += points;
        riskFactors.push(
          `Security warning - ${warning.eventType || "Unknown"}: ${
            warning.warning
          } (${points} points)`
        );
      }
    });

    // Store the number of critical and high risk events for use in getRiskLevel
    this.criticalEvents = criticalEvents;
    this.highRiskEvents = highRiskEvents;

    this.riskScore = score;
    this.riskFactors = riskFactors;
    return score;
  }

  /**
   * Get overall risk level based on risk score and critical event counts
   * @returns {string} Risk level (critical, high, medium, low, none)
   */
  getRiskLevel() {
    // If there are critical events, automatically assign critical risk
    if (this.criticalEvents > 0) {
      return "critical";
    }

    // If there are high risk events, automatically assign high risk
    if (this.highRiskEvents > 0) {
      return "high";
    }

    // For other events, use score thresholds
    if (this.warnings.length > 0 || this.anomalies.length > 0) {
      if (this.riskScore >= 100) return "critical";
      if (this.riskScore >= 75) return "high";
      if (this.riskScore >= 50) return "medium";
      if (this.riskScore > 20) return "low";
    }

    // If no warnings or anomalies, always return 'none'
    return "none";
  }

  /**
   * Get a summary of this user's activity
   * @returns {Object} User activity summary
   */
  getSummary() {
    // Calculate risk score if not already done
    if (
      this.riskScore === 0 &&
      (this.anomalies.length > 0 || this.warnings.length > 0)
    ) {
      this.calculateRiskScore();
    }

    return {
      userId: this.userId,
      username: this.username,
      loginStats: {
        totalDays: this.loginDays.length,
        firstLogin: this.loginDays[0] || "N/A",
        lastLogin: this.loginDays[this.loginDays.length - 1] || "N/A",
        uniqueIPs: this.ipAddresses.size,
        uniqueLocations: this.knownLocations.size,
      },
      warningsCount: {
        total: this.warnings.length,
        critical: this.warnings.filter((w) => w.severity === "critical").length,
        high: this.warnings.filter((w) => w.severity === "high").length,
        medium: this.warnings.filter((w) => w.severity === "medium").length,
        low: this.warnings.filter((w) => w.severity === "low" || !w.severity)
          .length,
      },
      scannedLogs: Object.fromEntries(this.scannedLogs),
      anomalies: this.anomalies,
      riskScore: this.riskScore,
      riskLevel: this.getRiskLevel(),
      criticalEvents: this.criticalEvents,
      highRiskEvents: this.highRiskEvents,
      riskFactors: this.riskFactors || [],
    };
  }

  /**
   * Get data formatted for CSV reporting
   * @returns {Object} Data for CSV report
   */
  getCSVData() {
    // Ensure risk score is calculated
    if (
      this.riskScore === 0 &&
      (this.anomalies.length > 0 || this.warnings.length > 0)
    ) {
      this.calculateRiskScore();
    }

    // Format risk factors explanation
    const riskFactorsExplanation =
      this.riskFactors && this.riskFactors.length > 0
        ? this.riskFactors.join("; ")
        : "No risk factors detected";

    // Base data that applies whether there are warnings or not
    const baseData = {
      username: this.username,
      userId: this.userId,
      firstLoginDate: this.loginDays[0] || "N/A",
      lastLoginDate: this.loginDays[this.loginDays.length - 1] || "N/A",
      loginDaysCount: this.loginDays.length,
      uniqueIPs: this.ipAddresses.size,
      scannedLogsCount: Array.from(this.scannedLogs.values()).reduce(
        (a, b) => a + b,
        0
      ),
      scannedEventTypes: Array.from(this.scannedLogs.keys()).join(", "),
      riskScore: this.riskScore,
      riskLevel: this.getRiskLevel(),
      anomalyCount: this.anomalies.length,
      criticalEvents: this.criticalEvents,
      highRiskEvents: this.highRiskEvents,
      riskFactorsExplanation: riskFactorsExplanation,
    };

    // If there are warnings, return one row for each warning
    if (this.warnings.length > 0) {
      return this.warnings.map((warning) => ({
        ...baseData,
        date: warning.date || "N/A",
        time: warning.timestamp || "N/A",
        warning: warning.warning || "N/A",
        severity: warning.severity || "low",
        eventType: warning.eventType || "N/A",
        clientIp: warning.clientIp || "N/A",
        sessionKey: warning.sessionKey || "N/A",
        context: warning.context || {},
      }));
    }

    // If no warnings, return a single row
    return [
      {
        ...baseData,
        date: "N/A",
        time: "N/A",
        warning: "No security risks detected",
        severity: "none",
        eventType: "N/A",
        clientIp: "N/A",
        sessionKey: "N/A",
        context: {},
      },
    ];
  }
}

module.exports = UserActivity;
