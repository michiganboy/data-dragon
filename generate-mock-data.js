/**
 * Generate mock data for testing the HTML report
 */
const fs = require('fs');
const path = require('path');

// Ensure output directories exist
const outputDir = path.join(process.cwd(), 'output');
const reportsDir = path.join(outputDir, 'reports');

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

if (!fs.existsSync(reportsDir)) {
  fs.mkdirSync(reportsDir, { recursive: true });
}

// Generate mock summary JSON
function generateMockSummaryData() {
  const now = new Date();
  
  // Calculate dates going back 6 months
  const sixMonthsAgo = new Date(now);
  sixMonthsAgo.setMonth(now.getMonth() - 6);
  
  const threeMonthsAgo = new Date(now);
  threeMonthsAgo.setMonth(now.getMonth() - 3);
  
  const oneMonthAgo = new Date(now);
  oneMonthAgo.setMonth(now.getMonth() - 1);
  
  // Create different event types
  const eventTypes = [
    'ReportExport', 
    'LoginAs', 
    'ContentDistribution',
    'DocumentAttachmentDownloads',
    'ApexExecution',
    'BulkApiRequest',
    'DataExport',
    'ContentDocumentLink',
    'Login',
    'URI'
  ];
  
  // Create event type counts
  const eventTypeCounts = {};
  eventTypes.forEach(type => {
    eventTypeCounts[type] = Math.floor(Math.random() * 100) + 20;
  });
  
  // Create users
  const users = [];
  const userCount = 15;
  
  for (let i = 1; i <= userCount; i++) {
    const userId = `00505${i}`;
    const username = `user${i}@example.com`;
    const riskScore = Math.floor(Math.random() * 100);
    
    let riskLevel;
    if (riskScore >= 75) riskLevel = 'critical';
    else if (riskScore >= 50) riskLevel = 'high';
    else if (riskScore >= 25) riskLevel = 'medium';
    else riskLevel = 'low';
    
    // Generate warnings across 6 months
    const warnings = [];
    const warningCount = Math.floor(Math.random() * 15) + 5; // 5-20 warnings
    
    for (let j = 0; j < warningCount; j++) {
      const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
      const severities = ['critical', 'high', 'medium', 'low'];
      const severity = severities[Math.floor(Math.random() * severities.length)];
      
      // Create warnings distributed across 6 months
      // More recent warnings are more common
      let warningDate;
      const randomValue = Math.random();
      if (randomValue < 0.4) {
        // 40% of warnings in the last month
        warningDate = new Date(now.getTime() - Math.random() * 30 * 24 * 60 * 60 * 1000);
      } else if (randomValue < 0.7) {
        // 30% of warnings in the 1-3 month range
        warningDate = new Date(oneMonthAgo.getTime() - Math.random() * 60 * 24 * 60 * 60 * 1000);
      } else {
        // 30% of warnings in the 3-6 month range
        warningDate = new Date(threeMonthsAgo.getTime() - Math.random() * 90 * 24 * 60 * 60 * 1000);
      }
      
      warnings.push({
        warning: getWarningMessageForEvent(eventType),
        severity,
        eventType,
        date: warningDate.toISOString(),
        timestamp: warningDate.toISOString(),
        userId,
        username,
        clientIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
        context: {
          details: `Details for ${eventType} event`
        }
      });
    }
    
    // Add login history spanning 6 months
    const loginTimes = [];
    const loginCount = Math.floor(Math.random() * 50) + 20; // 20-70 logins
    
    // Create a set of login days for this user
    const loginDays = new Set();
    
    for (let j = 0; j < loginCount; j++) {
      // Distribute logins across 6 months
      let loginTime;
      const randomValue = Math.random();
      if (randomValue < 0.5) {
        // 50% of logins in the last month
        loginTime = new Date(now.getTime() - Math.random() * 30 * 24 * 60 * 60 * 1000);
      } else if (randomValue < 0.8) {
        // 30% of logins in the 1-3 month range
        loginTime = new Date(oneMonthAgo.getTime() - Math.random() * 60 * 24 * 60 * 60 * 1000);
      } else {
        // 20% of logins in the 3-6 month range
        loginTime = new Date(threeMonthsAgo.getTime() - Math.random() * 90 * 24 * 60 * 60 * 1000);
      }
      
      // Add this day to the login days set
      loginDays.add(loginTime.toISOString().split('T')[0]);
      
      loginTimes.push({
        datetime: loginTime.toISOString(),
        timestamp: loginTime.toISOString(),
        sourceIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        userId,
        username: `user${i}@example.com`
      });
    }
    
    // Sort login times chronologically
    loginTimes.sort((a, b) => new Date(a.datetime) - new Date(b.datetime));
    
    // Add anomalies for some users
    const anomalies = [];
    if (Math.random() > 0.5) { // 50% of users have anomalies
      // Add 1-3 anomalies
      const anomalyCount = Math.floor(Math.random() * 3) + 1;
      
      for (let j = 0; j < anomalyCount; j++) {
        // Distribute anomalies across time periods
        let anomalyTime;
        const randomValue = Math.random();
        if (randomValue < 0.6) {
          // 60% of anomalies in the last month
          anomalyTime = new Date(now.getTime() - Math.random() * 30 * 24 * 60 * 60 * 1000);
        } else if (randomValue < 0.9) {
          // 30% of anomalies in the 1-3 month range
          anomalyTime = new Date(oneMonthAgo.getTime() - Math.random() * 60 * 24 * 60 * 60 * 1000);
        } else {
          // 10% of anomalies in the 3-6 month range
          anomalyTime = new Date(threeMonthsAgo.getTime() - Math.random() * 90 * 24 * 60 * 60 * 1000);
        }
        
        // Location change anomaly
        anomalies.push({
          type: 'rapid_ip_change',
          severity: Math.random() > 0.5 ? 'critical' : 'high',
          date: anomalyTime.toISOString(),
          description: 'Suspicious login location change',
          details: {
            from: '192.168.1.1',
            to: '10.0.0.1',
            hours: (Math.random() * 5 + 1).toFixed(1),
            prevLocation: getRandomLocation(),
            currLocation: getRandomLocation(),
            geoInfo: true,
            distanceDesc: `${getRandomLocation()} to ${getRandomLocation()} (${(Math.random() * 5 + 1).toFixed(1)} hours apart)`
          }
        });
      }
    }
    
    // Convert login days set to sorted array
    const loginDaysArray = Array.from(loginDays).sort();
    
    // Add user to summary
    users.push({
      userId,
      username,
      riskScore,
      riskLevel,
      criticalEvents: warnings.filter(w => w.severity === 'critical').length,
      highRiskEvents: warnings.filter(w => w.severity === 'high').length,
      loginActivity: {
        totalDays: loginDaysArray.length,
        firstLogin: loginDaysArray[0],
        lastLogin: loginDaysArray[loginDaysArray.length - 1]
      },
      warnings: warnings.map(w => ({
        date: w.date,
        timestamp: w.timestamp,
        warning: w.warning,
        severity: w.severity,
        eventType: w.eventType,
        context: w.context
      })),
      loginTimes: loginTimes,
      anomalies: anomalies
    });
  }
  
  // Calculate severity totals
  const criticalWarnings = users.reduce((total, user) => 
    total + user.warnings.filter(w => w.severity === 'critical').length, 0);
  const highWarnings = users.reduce((total, user) => 
    total + user.warnings.filter(w => w.severity === 'high').length, 0);
  const mediumWarnings = users.reduce((total, user) => 
    total + user.warnings.filter(w => w.severity === 'medium').length, 0);
  const lowWarnings = users.reduce((total, user) => 
    total + user.warnings.filter(w => w.severity === 'low').length, 0);
  
  // Create complete summary
  const summary = {
    generatedAt: now.toISOString(),
    stats: {
      totalUsers: users.length,
      totalFiles: Object.values(eventTypeCounts).reduce((a, b) => a + b, 0),
      totalWarnings: users.reduce((total, user) => total + user.warnings.length, 0),
      severeWarnings: criticalWarnings + highWarnings,
      eventTypesScanned: Object.keys(eventTypeCounts).length,
      highRiskUsers: users.filter(u => u.riskScore >= 50).length,
      htmlPath: path.join(reportsDir, 'security-report.html')
    },
    highRiskUsers: users.filter(u => u.riskScore >= 50).map(u => u.username),
    eventTypeCounts,
    warningsByEventType: createWarningsByEventType(users),
    userSummary: createUserSummary(users),
    monitoredUsers: users.map(u => u.username),
    riskConfig: {
      // Sample risk configuration
      ReportExport: { description: "Report export detected", severity: "high" },
      LoginAs: { description: "Login as another user detected", severity: "high" },
      ContentDistribution: { description: "Content sharing detected", severity: "critical" }
    }
  };
  
  return summary;
}

// Helper to create warnings by event type
function createWarningsByEventType(users) {
  const warningsByType = {};
  
  users.forEach(user => {
    user.warnings.forEach(warning => {
      if (!warningsByType[warning.eventType]) {
        warningsByType[warning.eventType] = [];
      }
      warningsByType[warning.eventType].push(warning);
    });
  });
  
  return warningsByType;
}

// Helper to create user summary
function createUserSummary(users) {
  const userSummary = {};
  
  users.forEach(user => {
    userSummary[user.username] = {
      userId: user.userId,
      warningCount: user.warnings.length,
      riskProfile: {
        critical: user.warnings.filter(w => w.severity === 'critical').length,
        high: user.warnings.filter(w => w.severity === 'high').length,
        medium: user.warnings.filter(w => w.severity === 'medium').length,
        low: user.warnings.filter(w => w.severity === 'low').length
      },
      loginActivity: user.loginActivity,
      riskScore: user.riskScore,
      riskLevel: user.riskLevel,
      criticalEvents: user.criticalEvents,
      highRiskEvents: user.highRiskEvents,
      warnings: user.warnings
    };
  });
  
  return userSummary;
}

// Generate random locations
function getRandomLocation() {
  const locations = [
    'New York, US',
    'Los Angeles, US',
    'Chicago, US',
    'Houston, US',
    'London, UK',
    'Paris, France',
    'Berlin, Germany',
    'Tokyo, Japan',
    'Sydney, Australia',
    'Toronto, Canada',
    'Mexico City, Mexico',
    'Beijing, China',
    'Mumbai, India',
    'Moscow, Russia',
    'São Paulo, Brazil'
  ];
  
  return locations[Math.floor(Math.random() * locations.length)];
}

// Generate warning messages based on event type
function getWarningMessageForEvent(eventType) {
  const messages = {
    ReportExport: [
      "Export of sensitive report detected",
      "Multiple report exports in short timeframe",
      "Report containing PII data exported"
    ],
    LoginAs: [
      "Admin logged in as regular user",
      "Suspicious login-as activity detected",
      "Multiple login-as events from admin"
    ],
    ContentDistribution: [
      "Public link created for sensitive document",
      "Multiple documents shared externally",
      "Document shared with external domain"
    ],
    DocumentAttachmentDownloads: [
      "Mass download of attachments",
      "Download of classified document",
      "Multiple sensitive file downloads"
    ],
    ApexExecution: [
      "Anonymous Apex execution detected",
      "Potentially harmful Apex code executed",
      "Unauthorized Apex execution"
    ],
    BulkApiRequest: [
      "Bulk API data extraction",
      "Abnormal volume of bulk API calls",
      "Off-hours bulk API usage"
    ],
    DataExport: [
      "Complete data export initiated",
      "Multiple data exports in short period",
      "Data export after hours"
    ],
    ContentDocumentLink: [
      "Mass sharing of documents",
      "Suspicious document access pattern",
      "Document access from unusual IP"
    ],
    Login: [
      "Login from unusual location",
      "Login at unusual time",
      "Failed login attempts followed by success"
    ],
    URI: [
      "Access to restricted admin page",
      "Multiple rapid page navigations",
      "Access attempt to unauthorized area"
    ]
  };
  
  const options = messages[eventType] || ["Suspicious activity detected"];
  return options[Math.floor(Math.random() * options.length)];
}

// Generate the mock data
const mockData = generateMockSummaryData();
fs.writeFileSync(
  path.join(outputDir, 'summary-report.json'), 
  JSON.stringify(mockData, null, 2)
);

console.log('Mock data generated successfully:');
console.log(`- JSON summary: ${path.join(outputDir, 'summary-report.json')}`);
console.log('You can now run test-report.js to generate a report from this data'); 