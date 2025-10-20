/**
 * Debug script to test the post-scanning report generation
 * This simulates what happens after log scanning is complete
 */

require('dotenv').config();
const reporting = require('./lib/reporting');
const UserActivity = require('./models/userActivity');
const RiskCorrelation = require('./lib/riskCorrelation');

async function testPostScanReportGeneration() {
  console.log("🧪 Testing post-scan report generation...");
  
  try {
    // Simulate the data that would exist after scanning
    const userMap = {
      '005000000000001': 'test@example.com',
      '005000000000002': 'test2@example.com'
    };
    
    const allScannedFiles = [
      { EventType: 'Login', logDate: '2024-01-01' },
      { EventType: 'ReportExport', logDate: '2024-01-01' },
      { EventType: 'ApexExecution', logDate: '2024-01-01' }
    ];
    
    const allWarnings = [
      {
        user: 'test@example.com',
        userId: '005000000000001',
        date: '2024-01-01',
        timestamp: '2024-01-01T10:00:00Z',
        warning: 'Test warning',
        severity: 'high',
        eventType: 'ReportExport',
        sessionKey: 'test-session',
        clientIp: '192.168.1.1',
        context: {}
      }
    ];
    
    // Create user activities (this is what might be failing)
    console.log("🧪 Creating user activities...");
    const userActivities = new Map();
    
    Object.entries(userMap).forEach(([userId, username]) => {
      const activity = new UserActivity(userId, username);
      
      // Add some mock login data
      activity.loginDays = ['2024-01-01', '2024-01-02'];
      activity.loginTimes = [
        {
          datetime: new Date('2024-01-01T09:00:00Z'),
          dayOfWeek: 1,
          hourOfDay: 9,
          weekend: false,
          sourceIp: '192.168.1.1'
        }
      ];
      
      // Add warnings for the first user
      if (userId === '005000000000001') {
        activity.addWarning(allWarnings[0]);
      }
      
      userActivities.set(userId, activity);
    });
    
    console.log("🧪 User activities created:", userActivities.size, "users");
    
    // Test risk correlation
    console.log("🧪 Testing risk correlation...");
    const riskCorrelation = new RiskCorrelation(userActivities);
    const correlationResults = riskCorrelation.analyzeAll();
    console.log("✅ Risk correlation completed");
    
    // Test summary generation
    console.log("🧪 Testing summary generation...");
    const summaryData = reporting.generateSummary(
      userMap,
      allScannedFiles,
      allWarnings,
      userActivities,
      riskCorrelation
    );
    console.log("✅ Summary generation completed");
    console.log("📊 Summary stats:", summaryData.stats);
    
    // Test HTML report generation
    console.log("🧪 Testing HTML report generation...");
    const htmlPath = await reporting.generateReport(
      { SUMMARY_CSV: './output/summary-report.csv' },
      userActivities,
      {
        title: 'Debug Post-Scan Report',
        organization: 'Debug Organization'
      }
    );
    console.log("✅ HTML report generated:", htmlPath);
    
    console.log("🎉 All post-scan steps completed successfully!");
    
  } catch (error) {
    console.error("❌ Error in post-scan test:", error.message);
    console.error("Stack trace:", error.stack);
  }
}

// Run the test
testPostScanReportGeneration();
