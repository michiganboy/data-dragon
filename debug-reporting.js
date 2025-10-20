/**
 * Debug script to test report generation independently
 * Run this to test if the reporting module works
 */

require('dotenv').config();
const reporting = require('./lib/reporting');
const UserActivity = require('./models/userActivity');

async function testReportGeneration() {
  console.log("🧪 Testing report generation...");
  
  try {
    // Create mock data
    const userMap = {
      '005000000000001': 'test@example.com',
      '005000000000002': 'test2@example.com'
    };
    
    const allScannedFiles = [
      { EventType: 'Login', logDate: '2024-01-01' },
      { EventType: 'ReportExport', logDate: '2024-01-01' }
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
    
    // Create mock user activities
    const userActivities = new Map();
    const activity1 = new UserActivity('005000000000001', 'test@example.com');
    activity1.addWarning(allWarnings[0]);
    userActivities.set('005000000000001', activity1);
    
    const activity2 = new UserActivity('005000000000002', 'test2@example.com');
    userActivities.set('005000000000002', activity2);
    
    console.log("🧪 Testing generateSummary...");
    const summary = reporting.generateSummary(
      userMap,
      allScannedFiles,
      allWarnings,
      userActivities,
      null
    );
    
    console.log("✅ Summary generated:", !!summary);
    console.log("📊 Summary stats:", summary.stats);
    
    // Test HTML report generation
    console.log("🧪 Testing HTML report generation...");
    const isReportingAvailable = reporting.isReportingAvailable();
    console.log("📋 HTML reporting available:", isReportingAvailable);
    
    if (isReportingAvailable) {
      const htmlPath = await reporting.generateReport(
        { SUMMARY_CSV: './output/summary-report.csv' },
        userActivities,
        {
          title: 'Debug Test Report',
          organization: 'Debug Organization'
        }
      );
      
      console.log("✅ HTML report generated:", htmlPath);
    } else {
      console.log("❌ HTML reporting not available - check EJS installation");
    }
    
  } catch (error) {
    console.error("❌ Error in report generation test:", error);
    console.error("Stack trace:", error.stack);
  }
}

// Run the test
testReportGeneration();
