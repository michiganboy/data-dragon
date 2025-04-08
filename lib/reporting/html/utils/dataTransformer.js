/**
 * Data transformation utilities for HTML reports
 * Transforms raw data into formats suitable for report templates
 */

/**
 * Transforms user activity data into a format suitable for the report
 * @param {Map<string, Object>} userActivities - Map of user activities
 * @returns {Object} Structured data for the report
 */
function transformUserData(userActivities) {
  if (!userActivities || !(userActivities instanceof Map)) {
    return { users: [], summary: getEmptySummary() };
  }
  
  const users = [];
  let totalRiskScore = 0;
  let criticalWarnings = 0;
  let highWarnings = 0;
  let mediumWarnings = 0;
  let lowWarnings = 0;
  
  // Process each user activity
  userActivities.forEach((activity, userId) => {
    // Skip if no activity data
    if (!activity) return;
    
    // Extract basic user info
    const userData = {
      id: userId,
      username: activity.username || 'Unknown User',
      riskScore: activity.riskScore || 0,
      riskLevel: activity.riskLevel || 'none',
      criticalEvents: activity.criticalEvents || 0,
      highRiskEvents: activity.highRiskEvents || 0,
      lastLoginDate: activity.lastLoginDate || null,
      loginCount: activity.loginTimes ? activity.loginTimes.length : 0,
      uniqueIPs: activity.uniqueIPs ? activity.uniqueIPs.size : 0,
      warnings: [],
      anomalies: [],
      timeline: [] // New field for timeline visualization
    };
    
    // Add warnings and build timeline simultaneously
    if (Array.isArray(activity.warnings)) {
      activity.warnings.forEach(warning => {
        const warningDate = warning.timestamp || warning.date;
        
        // Add to warnings array
        userData.warnings.push({
          date: warningDate,
          message: warning.warning || 'Unknown warning',
          severity: warning.severity || 'low',
          eventType: warning.eventType || 'Unknown',
          clientIp: warning.clientIp || '',
          context: warning.context || {}
        });
        
        // Add to timeline
        userData.timeline.push({
          date: warningDate,
          type: 'warning',
          eventType: warning.eventType || 'Unknown',
          severity: warning.severity || 'low',
          message: warning.warning || 'Unknown warning'
        });
        
        // Count by severity
        switch (warning.severity) {
          case 'critical': criticalWarnings++; break;
          case 'high': highWarnings++; break;
          case 'medium': mediumWarnings++; break;
          case 'low': lowWarnings++; break;
        }
      });
    }
    
    // Add anomalies and add to timeline
    if (Array.isArray(activity.anomalies)) {
      activity.anomalies.forEach(anomaly => {
        // Add to anomalies array
        userData.anomalies.push({
          type: anomaly.type || 'Unknown',
          description: anomaly.description || '',
          severity: anomaly.severity || 'low',
          details: anomaly.details || {},
          date: anomaly.date || anomaly.timestamp || null
        });
        
        // Add to timeline if it has a date
        if (anomaly.date || anomaly.timestamp) {
          userData.timeline.push({
            date: anomaly.date || anomaly.timestamp,
            type: 'anomaly',
            anomalyType: anomaly.type || 'Unknown',
            severity: anomaly.severity || 'low',
            message: anomaly.description || `${anomaly.type} anomaly detected`
          });
        }
      });
    }
    
    // Add logins to timeline
    if (Array.isArray(activity.loginTimes)) {
      activity.loginTimes.forEach(login => {
        if (login.datetime) {
          userData.timeline.push({
            date: login.datetime,
            type: 'login',
            sourceIp: login.sourceIp || 'Unknown',
            weekend: login.weekend || false,
            hourOfDay: login.hourOfDay || 0
          });
        }
      });
    }
    
    // Sort timeline by date
    userData.timeline.sort((a, b) => {
      const dateA = new Date(a.date);
      const dateB = new Date(b.date);
      return dateA - dateB;
    });
    
    // Group warnings by event type for visualization
    userData.warningsByType = {};
    userData.warnings.forEach(warning => {
      const eventType = warning.eventType || 'Unknown';
      if (!userData.warningsByType[eventType]) {
        userData.warningsByType[eventType] = [];
      }
      userData.warningsByType[eventType].push(warning);
    });
    
    // Add to total risk score
    totalRiskScore += userData.riskScore;
    
    // Add user to list
    users.push(userData);
  });
  
  // Sort users by risk score (highest first)
  users.sort((a, b) => b.riskScore - a.riskScore);
  
  // Create summary data
  const summary = {
    userCount: users.length,
    averageRiskScore: users.length ? Math.round(totalRiskScore / users.length) : 0,
    highRiskUsers: users.filter(u => u.riskScore > 50).length,
    criticalWarnings,
    highWarnings,
    mediumWarnings,
    lowWarnings,
    totalWarnings: criticalWarnings + highWarnings + mediumWarnings + lowWarnings,
    topRiskUsers: users.slice(0, 5), // Top 5 riskiest users
    eventTypeTotals: getEventTypeTotals(users)
  };
  
  return { users, summary };
}

/**
 * Creates empty summary object for when no data is available
 * @returns {Object} Empty summary structure
 */
function getEmptySummary() {
  return {
    userCount: 0,
    averageRiskScore: 0,
    highRiskUsers: 0,
    criticalWarnings: 0, 
    highWarnings: 0,
    mediumWarnings: 0,
    lowWarnings: 0,
    totalWarnings: 0,
    topRiskUsers: [],
    eventTypeTotals: {}
  };
}

/**
 * Calculates totals for each event type across all users
 * @param {Array} users - Processed user data
 * @returns {Object} Event type totals
 */
function getEventTypeTotals(users) {
  const totals = {};
  
  users.forEach(user => {
    Object.keys(user.warningsByType || {}).forEach(eventType => {
      if (!totals[eventType]) {
        totals[eventType] = 0;
      }
      totals[eventType] += user.warningsByType[eventType].length;
    });
  });
  
  return totals;
}

/**
 * Prepares data for risk distribution chart
 * @param {Object} summary - Summary data
 * @returns {Object} Chart data
 */
function prepareRiskDistributionData(summary) {
  return {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    values: [
      summary.criticalWarnings,
      summary.highWarnings,
      summary.mediumWarnings,
      summary.lowWarnings
    ]
  };
}

/**
 * Formats a date for display in the report
 * @param {string|Date} date - Date to format
 * @param {boolean} includeTime - Whether to include time
 * @returns {string} Formatted date string
 */
function formatDate(date, includeTime = false) {
  if (!date) return 'N/A';
  
  const dateObj = new Date(date);
  if (isNaN(dateObj.getTime())) return 'Invalid Date';
  
  const options = { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric'
  };
  
  if (includeTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
  }
  
  return dateObj.toLocaleDateString('en-US', options);
}

/**
 * Gets the appropriate CSS class for a risk level
 * @param {string} riskLevel - Risk level (critical, high, medium, low, none)
 * @returns {string} CSS class name
 */
function getRiskLevelClass(riskLevel) {
  switch(riskLevel.toLowerCase()) {
    case 'critical': return 'risk-critical';
    case 'high': return 'risk-high';
    case 'medium': return 'risk-medium';
    case 'low': return 'risk-low';
    default: return 'risk-none';
  }
}

module.exports = {
  transformUserData,
  prepareRiskDistributionData,
  formatDate,
  getRiskLevelClass
}; 