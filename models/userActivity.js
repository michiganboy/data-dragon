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
      // Get standardized fields - prioritize TIMESTAMP_DERIVED for Salesforce event logs
      const timestamp = utils.getStandardizedField(
        record,
        ["TIMESTAMP_DERIVED", "LoginTime", "LOGIN_TIME", "TIMESTAMP"],
        null
      );

      // Extract date and time
      if (timestamp) {
        // Handle ISO format timestamps like 2025-03-10T19:00:09.648Z
        const loginDate = new Date(timestamp);

        // Check if we got a valid date
        if (!isNaN(loginDate.getTime())) {
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
            sourceIp: utils.getStandardizedField(
              record,
              ["SOURCE_IP", "CLIENT_IP", "SourceIp", "IP_ADDRESS"],
              null
            ),
          });
        }
      }

      // Track IP addresses using multiple possible field names
      const ipAddress = utils.getStandardizedField(
        record,
        ["SOURCE_IP", "CLIENT_IP", "SourceIp", "IP_ADDRESS"],
        null
      );

      if (ipAddress) {
        const currentCount = this.ipAddresses.get(ipAddress) || 0;
        this.ipAddresses.set(ipAddress, currentCount + 1);
      }

      // Track location if available
      const locationId = utils.getStandardizedField(
        record,
        ["LOGIN_GEO_ID", "LoginGeoId", "GEO_ID"],
        null
      );

      if (locationId) {
        this.knownLocations.add(locationId);
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
      console.log(`[DEBUG] Not enough login times to analyze patterns for user ${this.username}`);
      return [];
    }

    console.log(`[DEBUG] Analyzing login patterns for user ${this.username} with ${this.loginTimes.length} logins`);
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
    console.log(`[DEBUG] Checking rapid IP changes for ${this.username}`);
    const ipAnomalies = this.detectRapidIPChanges();
    console.log(`[DEBUG] Found ${ipAnomalies.length} IP anomalies for ${this.username}`);
    
    if (ipAnomalies.length > 0) {
      ipAnomalies.forEach((anomaly) => {
        // Create a more descriptive message using location data if available
        let description = "";
        let severity = "critical"; // Set all geographic IP changes to critical
        
        if (anomaly.geoInfo && anomaly.distanceDesc) {
          // Format a clear, human-readable message
          const timeDiff = anomaly.hours < 1 
            ? `${Math.round(anomaly.hours * 60)} minutes` 
            : `${anomaly.hours} hours`;
            
          description = `Suspicious rapid location change detected: User logged in from ${anomaly.prevLocation} at ${anomaly.formattedPrevTime}, then from ${anomaly.currLocation} at ${anomaly.formattedCurrTime} (${timeDiff} apart)`;
          
          // All geographic location changes are now critical severity
          if (anomaly.severityMultiplier) {
            anomaly.severityMultiplier = 2.0; // Ensure high multiplier for all geo changes
          }
          
          console.log(`[DEBUG] Added location anomaly: ${description}`);
        } else {
          // Fallback for cases where geo lookup failed
          description = `Rapid IP change from ${anomaly.from} to ${anomaly.to} (${anomaly.hours} hours apart)`;
          if (anomaly.prevLocation && anomaly.currLocation) {
            description += `: ${anomaly.prevLocation} → ${anomaly.currLocation}`;
          }
          
          console.log(`[DEBUG] Added IP change anomaly (no geo): ${description}`);
        }
        
        anomalies.push({
          type: "rapid_ip_change",
          severity: severity,
          description: description,
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
    
    console.log(`[DEBUG] Total anomalies found for ${this.username}: ${anomalies.length}`);

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
   * Detect suspicious rapid changes in IP addresses based on geographic location
   * @private
   * @returns {Object[]} Array of rapid IP change anomalies
   */
  detectRapidIPChanges() {
    const anomalies = [];
    const recentLogins = [...this.loginTimes];
    const geoip = require('geoip-lite');
    
    // Debug output
    console.log(`[DEBUG] Checking for rapid IP changes for user ${this.username} (${this.userId})`);
    console.log(`[DEBUG] Have ${recentLogins.length} login times to analyze`);

    // Sort login times chronologically
    recentLogins.sort((a, b) => a.datetime - b.datetime);

    // Need at least 2 logins to detect changes
    if (recentLogins.length < 2) {
      console.log(`[DEBUG] Not enough logins to check for rapid IP changes for user ${this.username}`);
      return anomalies;
    }

    // Check for logins from different IPs within a short timeframe
    for (let i = 1; i < recentLogins.length; i++) {
      const prevLogin = recentLogins[i - 1];
      const currLogin = recentLogins[i];

      // Debug the IPs
      console.log(`[DEBUG] Comparing IPs: ${prevLogin.sourceIp || 'unknown'} vs ${currLogin.sourceIp || 'unknown'}`);

      // If IP information isn't available, skip
      if (!prevLogin.sourceIp || !currLogin.sourceIp) {
        console.log(`[DEBUG] Missing source IP for comparison, skipping`);
        continue;
      }

      // Skip if same IP
      if (prevLogin.sourceIp === currLogin.sourceIp) {
        console.log(`[DEBUG] Same IP, skipping`);
        continue;
      }

      // Calculate hours between logins
      const hoursDiff = (currLogin.datetime - prevLogin.datetime) / (1000 * 60 * 60);
      console.log(`[DEBUG] Time difference: ${hoursDiff.toFixed(2)} hours`);

      // Only check within 4 hour window (restored from 1 hour for wider detection)
      if (hoursDiff >= 4) {
        console.log(`[DEBUG] Time difference exceeds threshold (4 hours), skipping`);
        continue;
      }

      // Look up geographic locations
      const prevGeo = geoip.lookup(prevLogin.sourceIp);
      const currGeo = geoip.lookup(currLogin.sourceIp);
      
      console.log(`[DEBUG] Geo lookup results: Previous IP ${prevLogin.sourceIp}: ${prevGeo ? JSON.stringify(prevGeo) : 'lookup failed'}`);
      console.log(`[DEBUG] Geo lookup results: Current IP ${currLogin.sourceIp}: ${currGeo ? JSON.stringify(currGeo) : 'lookup failed'}`);

      // Format time for better readability
      const prevTime = prevLogin.datetime.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: 'numeric',
        hour12: true
      });
      
      const currTime = currLogin.datetime.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: 'numeric',
        hour12: true
      });

      // If either geo lookup failed, fall back to IP comparison
      if (!prevGeo || !currGeo) {
        console.log(`[DEBUG] One or both geo lookups failed, using fallback IP comparison`);
        anomalies.push({
          from: prevLogin.sourceIp,
          to: currLogin.sourceIp,
          hours: hoursDiff.toFixed(2),
          prevTime: prevLogin.datetime.toISOString(),
          currTime: currLogin.datetime.toISOString(),
          formattedPrevTime: prevTime,
          formattedCurrTime: currTime,
          prevLocation: prevGeo ? `${prevGeo.country}${prevGeo.city ? ', ' + prevGeo.city : ''}` : 'Unknown',
          currLocation: currGeo ? `${currGeo.country}${currGeo.city ? ', ' + currGeo.city : ''}` : 'Unknown',
          geoInfo: false
        });
        continue;
      }

      // Skip if same country and city (same location despite different IPs)
      if (prevGeo.country === currGeo.country && prevGeo.city === currGeo.city) {
        console.log(`[DEBUG] Same location (country and city) despite different IPs, skipping`);
        continue;
      }

      // Prepare clean location strings
      const prevLocation = prevGeo.city ? `${prevGeo.city}, ${prevGeo.country}` : prevGeo.country;
      const currLocation = currGeo.city ? `${currGeo.city}, ${currGeo.country}` : currGeo.country;

      console.log(`[DEBUG] Different locations detected: ${prevLocation} to ${currLocation}`);

      // Now any geographic change is considered high risk
      // Higher severity if countries are different
      if (prevGeo.country !== currGeo.country) {
        console.log(`[DEBUG] ADDING LOCATION ANOMALY: Different countries detected`);
        anomalies.push({
          from: prevLogin.sourceIp,
          to: currLogin.sourceIp,
          hours: hoursDiff.toFixed(2),
          prevTime: prevLogin.datetime.toISOString(),
          currTime: currLogin.datetime.toISOString(),
          formattedPrevTime: prevTime,
          formattedCurrTime: currTime,
          prevLocation: prevLocation,
          currLocation: currLocation,
          geoInfo: true,
          severityMultiplier: 2.0, // Maximum severity for country changes
          distanceDesc: `${prevLocation} to ${currLocation} (${hoursDiff < 0.016 ? Math.round(hoursDiff * 60 * 60) + " seconds" : hoursDiff < 1 ? Math.round(hoursDiff * 60) + " minutes" : hoursDiff.toFixed(2) + " hours"} apart)`
        });
      }
      // City changes within the same country are also treated as high risk now
      else if (prevGeo.city !== currGeo.city) {
        console.log(`[DEBUG] ADDING LOCATION ANOMALY: Different cities detected in same country`);
        anomalies.push({
          from: prevLogin.sourceIp,
          to: currLogin.sourceIp,
          hours: hoursDiff.toFixed(2),
          prevTime: prevLogin.datetime.toISOString(),
          currTime: currLogin.datetime.toISOString(),
          formattedPrevTime: prevTime,
          formattedCurrTime: currTime,
          prevLocation: prevLocation,
          currLocation: currLocation,
          geoInfo: true,
          severityMultiplier: 2.0, // Increased severity for city changes too
          distanceDesc: `${prevLocation} to ${currLocation} (${hoursDiff < 0.016 ? Math.round(hoursDiff * 60 * 60) + " seconds" : hoursDiff < 1 ? Math.round(hoursDiff * 60) + " minutes" : hoursDiff.toFixed(2) + " hours"} apart)`
        });
      }
    }

    console.log(`[DEBUG] Finished checking rapid IP changes, found ${anomalies.length} anomalies`);
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
          // Give extra points to geographical location changes
          if (anomaly.type === 'rapid_ip_change' && anomaly.details && anomaly.details.geoInfo) {
            points = 50; // Higher points for geographical location changes
          } else {
            points = 40;
          }
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

      // Apply additional multiplier if specified in the anomaly details
      if (anomaly.details && anomaly.details.severityMultiplier) {
        points = Math.round(points * anomaly.details.severityMultiplier);
      }

      score += points;
      
      // Create a more informative risk factor message
      let riskMessage = `Anomaly - ${anomaly.type}`;
      
      // For rapid IP changes, include location info if available
      if (anomaly.type === 'rapid_ip_change' && anomaly.details) {
        if (anomaly.details.geoInfo) {
          // New format: Location-based message with time information 
          const prevLoc = anomaly.details.prevLocation || "Unknown location";
          const currLoc = anomaly.details.currLocation || "Unknown location";
          const hoursDiff = anomaly.details.hours || "unknown";
          
          // Format time difference for better readability
          let timeDesc = "";
          if (hoursDiff !== "unknown") {
            const hourValue = parseFloat(hoursDiff);
            if (hourValue < 0.016) { // Less than 1 minute
              timeDesc = `(${Math.round(hourValue * 60 * 60)} seconds apart)`;
            } else if (hourValue < 1) { // Less than 1 hour
              timeDesc = `(${Math.round(hourValue * 60)} minutes apart)`;
            } else {
              timeDesc = `(${hourValue} hours apart)`;
            }
          }
          
          riskMessage = `CRITICAL - Suspicious login location change: ${prevLoc.trim()} to ${currLoc.trim()} ${timeDesc}`;
        } else if (anomaly.details.prevLocation && anomaly.details.currLocation) {
          const prevLoc = anomaly.details.prevLocation || "Unknown location";
          const currLoc = anomaly.details.currLocation || "Unknown location";
          const hoursDiff = anomaly.details.hours || "unknown";
          
          // Format time difference for better readability
          let timeDesc = "";
          if (hoursDiff !== "unknown") {
            const hourValue = parseFloat(hoursDiff);
            if (hourValue < 0.016) { // Less than 1 minute
              timeDesc = `(${Math.round(hourValue * 60 * 60)} seconds apart)`;
            } else if (hourValue < 1) { // Less than 1 hour
              timeDesc = `(${Math.round(hourValue * 60)} minutes apart)`;
            } else {
              timeDesc = `(${hourValue} hours apart)`;
            }
          }
          
          riskMessage = `CRITICAL - IP address change: ${prevLoc.trim()} to ${currLoc.trim()} ${timeDesc}`;
        }
      }
      
      riskFactors.push(`${riskMessage} (${points} points)`);
    });

    // Add points for each warning
    this.warnings.forEach((warning) => {
      let points = 0;
      switch (warning.severity) {
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
      
      // Simply prefix the warning message with "Warning - " without modifying content
      riskFactors.push(`Warning - ${warning.warning} (${points} points)`);
    });

    // Store the results
    this.riskScore = score;
    this.riskFactors = riskFactors;
    this.criticalEvents = criticalEvents;
    this.highRiskEvents = highRiskEvents;
  }

  /**
   * Format risk factors to ensure they're human-readable
   * This helps clean up the data before it's used in reports
   * @private
   */
  formatRiskFactors() {
    if (!this.riskFactors || this.riskFactors.length === 0) return;

    this.riskFactors = this.riskFactors.map(factor => {
      // First, always remove the point values
      const cleanFactor = factor.replace(/ \(\d+ points\)$/, '');
      
      // Handle location change messages with the special prefix
      if (cleanFactor.startsWith('LOCATION_CHANGE:')) {
        // Extract the locations and timing info
        const locationMatch = cleanFactor.match(/: ([^:]+) to ([^(]+)(\([^)]+\))?/);
        if (locationMatch && locationMatch.length >= 3) {
          const fromLocation = locationMatch[1].trim();
          const toLocation = locationMatch[2].trim();
          const timeInfo = locationMatch[3] ? ` ${locationMatch[3].trim()}` : '';
          return `Suspicious login location change: ${fromLocation} to ${toLocation}${timeInfo}`;
        }
      }
      
      return cleanFactor;
    });
  }
}

module.exports = UserActivity;