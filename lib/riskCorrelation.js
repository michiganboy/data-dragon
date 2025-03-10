// Risk Correlation Engine
// This module analyzes relationships between login patterns and security events

const utils = require("./utils");

/**
 * RiskCorrelation class to analyze relationships between login patterns and security events
 */
class RiskCorrelation {
  /**
   * Create a new RiskCorrelation instance
   * @param {Map<string, UserActivity>} userActivities - Map of userId -> UserActivity
   * @param {Object} config - Configuration options
   */
  constructor(userActivities, config = {}) {
    this.userActivities = userActivities;
    this.config = {
      // Time window (in hours) for correlating login and risk events
      correlationWindow: config.correlationWindow || 2,
      // Weight factors for different correlation types
      weights: {
        unusualLoginTime: config.weights?.unusualLoginTime || 1.5,
        multipleLocations: config.weights?.multipleLocations || 2.0,
        rapidIpChange: config.weights?.rapidIpChange || 2.5,
        weekendActivity: config.weights?.weekendActivity || 1.2,
        outsideBusinessHours: config.weights?.outsideBusinessHours || 1.3,
      },
      ...config,
    };

    this.correlations = new Map(); // userId -> correlations
  }

  /**
   * Analyze all users and identify risk correlations
   * @returns {Map} Map of userId -> correlation results
   */
  analyzeAll() {
    utils.log("info", "Analyzing risk correlations for all users...");

    this.userActivities.forEach((activity, userId) => {
      const correlations = this.analyzeUserRiskCorrelations(activity);
      this.correlations.set(userId, correlations);
    });

    return this.correlations;
  }

  /**
   * Analyze a specific user's activity for risk correlations
   * @param {UserActivity} userActivity - User activity object
   * @returns {Object} Correlation analysis results
   */
  analyzeUserRiskCorrelations(userActivity) {
    // Skip analysis if no warnings
    if (!userActivity.warnings || userActivity.warnings.length === 0) {
      return {
        userId: userActivity.userId,
        username: userActivity.username,
        correlationCount: 0,
        correlations: [],
        correlationScore: 0,
      };
    }

    const correlations = [];

    // Analyze each warning for correlations with login behaviors
    userActivity.warnings.forEach((warning) => {
      // Look for temporal correlations with login anomalies
      const temporalCorrelations = this.findTemporalCorrelations(
        userActivity,
        warning
      );
      if (temporalCorrelations.length > 0) {
        correlations.push(...temporalCorrelations);
      }

      // Analyze behavioral correlations
      const behavioralCorrelations = this.findBehavioralCorrelations(
        userActivity,
        warning
      );
      if (behavioralCorrelations.length > 0) {
        correlations.push(...behavioralCorrelations);
      }
    });

    // Calculate overall correlation score
    const correlationScore = correlations.reduce(
      (total, corr) => total + corr.weight,
      0
    );

    return {
      userId: userActivity.userId,
      username: userActivity.username,
      correlationCount: correlations.length,
      correlations,
      correlationScore,
    };
  }

  /**
   * Find temporal correlations between login anomalies and security warnings
   * @param {UserActivity} userActivity - User activity object
   * @param {Object} warning - Warning object
   * @returns {Array} Array of correlation objects
   */
  findTemporalCorrelations(userActivity, warning) {
    const correlations = [];

    // Skip if warning doesn't have timestamp info
    if (!warning.timestamp && !warning.date) {
      return correlations;
    }

    // Get warning timestamp
    const warningTime = warning.timestamp
      ? new Date(warning.timestamp)
      : new Date(`${warning.date}T00:00:00Z`);

    // Check for login anomalies within the correlation window
    userActivity.anomalies.forEach((anomaly) => {
      // For anomalies with specific timestamps
      if (anomaly.details && anomaly.details.currTime) {
        const anomalyTime = new Date(anomaly.details.currTime);
        const hoursDiff =
          Math.abs(anomalyTime - warningTime) / (1000 * 60 * 60);

        // If anomaly occurred within correlation window of the warning
        if (hoursDiff <= this.config.correlationWindow) {
          correlations.push({
            type: "temporal",
            subtype: anomaly.type,
            warning: {
              id: warning.id || `w-${warning.date}-${warning.eventType}`,
              type: warning.eventType,
              severity: warning.severity,
              time: warningTime,
            },
            anomaly: {
              type: anomaly.type,
              severity: anomaly.severity,
              time: anomalyTime,
            },
            timeDifference: hoursDiff.toFixed(2),
            weight: this.getCorrelationWeight(
              anomaly.type,
              warning.severity,
              hoursDiff
            ),
            description: `${
              anomaly.description
            } occurred within ${hoursDiff.toFixed(2)} hours of ${
              warning.warning
            }`,
          });
        }
      }
    });

    return correlations;
  }

  /**
   * Find behavioral correlations between user login patterns and security warnings
   * @param {UserActivity} userActivity - User activity object
   * @param {Object} warning - Warning object
   * @returns {Array} Array of correlation objects
   */
  findBehavioralCorrelations(userActivity, warning) {
    const correlations = [];

    // Skip if warning doesn't have date info
    if (!warning.date) {
      return correlations;
    }

    // Get warning date and hour
    const warningDate = warning.timestamp
      ? new Date(warning.timestamp)
      : new Date(`${warning.date}T00:00:00Z`);
    const warningHour = warningDate.getHours();
    const isWeekend = warningDate.getDay() === 0 || warningDate.getDay() === 6;

    // 1. Check if warning occurred outside normal working hours
    const timePatterns = userActivity.detectTimePatterns
      ? userActivity.detectTimePatterns()
      : { normalHours: [9, 10, 11, 12, 13, 14, 15, 16, 17] };

    if (
      timePatterns.normalHours &&
      !timePatterns.normalHours.includes(warningHour)
    ) {
      correlations.push({
        type: "behavioral",
        subtype: "outside_business_hours",
        warning: {
          id: warning.id || `w-${warning.date}-${warning.eventType}`,
          type: warning.eventType,
          severity: warning.severity,
          time: warningDate,
        },
        details: {
          hour: warningHour,
          normalHours: timePatterns.normalHours,
        },
        weight: this.config.weights.outsideBusinessHours,
        description: `Security event occurred outside normal working hours (${warningHour}:00)`,
      });
    }

    // 2. Check if warning occurred on weekend
    if (isWeekend) {
      // Check if user normally works on weekends
      const weekendActivity = userActivity.detectWeekendAnomalies
        ? userActivity.detectWeekendAnomalies()
        : { rareWeekendUser: true };

      if (weekendActivity.rareWeekendUser) {
        correlations.push({
          type: "behavioral",
          subtype: "weekend_activity",
          warning: {
            id: warning.id || `w-${warning.date}-${warning.eventType}`,
            type: warning.eventType,
            severity: warning.severity,
            time: warningDate,
          },
          details: {
            dayOfWeek: warningDate.getDay(),
            isWeekend: true,
          },
          weight: this.config.weights.weekendActivity,
          description: `Security event occurred on weekend for user who rarely works weekends`,
        });
      }
    }

    // 3. Check if warning came from unusual IP/location
    if (warning.clientIp) {
      const ipAddresses = Array.from(
        userActivity.ipAddresses ? userActivity.ipAddresses.keys() : []
      );

      // If we have IP history and this IP isn't common for user
      if (ipAddresses.length > 0 && !ipAddresses.includes(warning.clientIp)) {
        // If the user has 2+ IPs and this is a new one, that's suspicious
        if (ipAddresses.length >= 2) {
          correlations.push({
            type: "behavioral",
            subtype: "unusual_ip",
            warning: {
              id: warning.id || `w-${warning.date}-${warning.eventType}`,
              type: warning.eventType,
              severity: warning.severity,
              time: warningDate,
            },
            details: {
              ip: warning.clientIp,
              knownIps: ipAddresses,
            },
            weight: this.config.weights.multipleLocations,
            description: `Security event from unusual IP address: ${warning.clientIp}`,
          });
        }
      }
    }

    return correlations;
  }

  /**
   * Calculate weight for a correlation based on anomaly type and warning severity
   * @param {string} anomalyType - Type of anomaly
   * @param {string} warningSeverity - Severity of the warning
   * @param {number} timeDifference - Time difference in hours between anomaly and warning
   * @returns {number} Correlation weight
   */
  getCorrelationWeight(anomalyType, warningSeverity, timeDifference) {
    // Base weight from anomaly type
    let weight = 1.0;

    switch (anomalyType) {
      case "rapid_ip_change":
        weight = this.config.weights.rapidIpChange;
        break;
      case "unusual_hours":
        weight = this.config.weights.unusualLoginTime;
        break;
      case "unusual_ip":
        weight = this.config.weights.multipleLocations;
        break;
      case "weekend_activity":
        weight = this.config.weights.weekendActivity;
        break;
    }

    // Adjust weight based on warning severity
    switch (warningSeverity) {
      case "critical":
        weight *= 2.0;
        break;
      case "high":
        weight *= 1.5;
        break;
      case "medium":
        weight *= 1.2;
        break;
    }

    // Adjust weight based on time proximity (closer = higher weight)
    if (timeDifference < 0.5) {
      // Within 30 minutes
      weight *= 1.5;
    } else if (timeDifference < 1.0) {
      // Within 1 hour
      weight *= 1.2;
    }

    return weight;
  }

  /**
   * Get correlation results for a specific user
   * @param {string} userId - User ID
   * @returns {Object|null} Correlation results or null if not found
   */
  getUserCorrelations(userId) {
    return this.correlations.get(userId) || null;
  }

  /**
   * Get correlation results for all users
   * @returns {Object[]} Array of correlation results
   */
  getAllCorrelations() {
    return Array.from(this.correlations.values());
  }

  /**
   * Get high-risk users based on correlation score
   * @param {number} threshold - Score threshold (default: 10)
   * @returns {Object[]} Array of high-risk user correlation results
   */
  getHighRiskUsers(threshold = 10) {
    return this.getAllCorrelations()
      .filter((result) => result.correlationScore >= threshold)
      .sort((a, b) => b.correlationScore - a.correlationScore);
  }
}

module.exports = RiskCorrelation;
