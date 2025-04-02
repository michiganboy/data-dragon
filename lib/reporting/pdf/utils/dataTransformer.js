/**
 * Data transformation utilities for PDF reports
 * Transforms raw data into formats suitable for PDF rendering
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
      anomalies: []
    };
    
    // Add warnings
    if (Array.isArray(activity.warnings)) {
      activity.warnings.forEach(warning => {
        userData.warnings.push({
          date: warning.timestamp || warning.date,
          message: warning.warning || 'Unknown warning',
          severity: warning.severity || 'low',
          eventType: warning.eventType || 'Unknown',
          clientIp: warning.clientIp || '',
          context: warning.context || {}
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
    
    // Add anomalies
    if (Array.isArray(activity.anomalies)) {
      activity.anomalies.forEach(anomaly => {
        userData.anomalies.push({
          type: anomaly.type || 'Unknown',
          description: anomaly.description || '',
          severity: anomaly.severity || 'low',
          details: anomaly.details || {}
        });
      });
    }
    
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
    topRiskUsers: users.slice(0, 5) // Top 5 riskiest users
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
    topRiskUsers: []
  };
}

/**
 * Prepares data for risk distribution chart
 * @param {Object} summary - Summary data
 * @returns {Object} Chart data
 */
function prepareRiskDistributionData(summary) {
  return {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      label: 'Warnings by Severity',
      data: [
        summary.criticalWarnings,
        summary.highWarnings,
        summary.mediumWarnings,
        summary.lowWarnings
      ],
      backgroundColor: [
        '#ff0000',
        '#ff9900',
        '#ffcc00',
        '#3399ff'
      ]
    }]
  };
}

/**
 * Groups warnings by event type for visualization
 * @param {Array} users - User data array
 * @returns {Object} Warning counts by event type
 */
function groupWarningsByEventType(users) {
  const eventTypes = {};
  
  users.forEach(user => {
    if (!user.warnings) return;
    
    user.warnings.forEach(warning => {
      const eventType = warning.eventType || 'Unknown';
      if (!eventTypes[eventType]) {
        eventTypes[eventType] = { count: 0, severity: {} };
      }
      
      eventTypes[eventType].count++;
      
      // Count by severity
      const severity = warning.severity || 'low';
      if (!eventTypes[eventType].severity[severity]) {
        eventTypes[eventType].severity[severity] = 0;
      }
      eventTypes[eventType].severity[severity]++;
    });
  });
  
  // Convert to array and sort by count
  return Object.entries(eventTypes)
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.count - a.count);
}

/**
 * Extracts location data from warnings for geographic visualization
 * @param {Array} users - User data array
 * @returns {Array} Location data
 */
function extractLocationData(users) {
  const locations = [];
  
  users.forEach(user => {
    if (!user.warnings) return;
    
    user.warnings.forEach(warning => {
      // Check if location related warning
      if (warning.eventType === 'LocationChange' || warning.eventType === 'InternationalLogin') {
        if (warning.context && (warning.context.curr_location || warning.context.prev_location)) {
          // From location if available
          if (warning.context.prev_location) {
            locations.push({
              location: warning.context.prev_location,
              user: user.username,
              type: 'previous',
              eventType: warning.eventType
            });
          }
          
          // To location if available
          if (warning.context.curr_location) {
            locations.push({
              location: warning.context.curr_location,
              user: user.username,
              type: 'current',
              eventType: warning.eventType
            });
          }
        }
      }
    });
  });
  
  return locations;
}

module.exports = {
  transformUserData,
  prepareRiskDistributionData,
  groupWarningsByEventType,
  extractLocationData
}; 