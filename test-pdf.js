/**
 * Test script for HTML/PDF report generation
 */
require('dotenv').config();
const path = require('path');
const htmlReportGenerator = require('./lib/reporting/html/generator');
const UserActivity = require('./models/userActivity');

// Create a minimal test dataset
function createTestData() {
  const userActivities = new Map();
  
  // Create a test user with high risk
  const user1 = new UserActivity('001', 'test.user@example.com');
  user1.riskScore = 75;
  user1.riskLevel = 'high';
  user1.criticalEvents = 1;
  user1.highRiskEvents = 3;
  
  // Add login history
  const now = new Date();
  user1.loginDays = [
    '2023-04-01',
    '2023-04-02',
    '2023-04-03',
  ];
  
  user1.loginTimes = [
    {
      datetime: now,
      dayOfWeek: now.getDay(),
      hourOfDay: now.getHours(),
      sourceIp: '192.168.1.1'
    }
  ];
  
  // Add some test warnings
  user1.warnings = [
    {
      date: now.toISOString(),
      timestamp: now.toISOString(),
      message: 'Suspicious login location change: US to Australia (2 hours)',
      severity: 'critical',
      eventType: 'LocationChange'
    },
    {
      date: new Date(now.getTime() - 86400000).toISOString(), // Yesterday
      timestamp: new Date(now.getTime() - 86400000).toISOString(),
      message: 'Report export detected',
      severity: 'high',
      eventType: 'ReportExport'
    },
    {
      date: new Date(now.getTime() - 172800000).toISOString(), // 2 days ago
      timestamp: new Date(now.getTime() - 172800000).toISOString(),
      message: 'Multiple dashboard access (35 in 1 hour)',
      severity: 'medium',
      eventType: 'Dashboard'
    }
  ];
  
  // Add to map
  userActivities.set('001', user1);
  
  // Add a second user with low risk
  const user2 = new UserActivity('002', 'low.risk@example.com');
  user2.riskScore = 15;
  user2.riskLevel = 'low';
  user2.loginDays = ['2023-04-01', '2023-04-02'];
  user2.warnings = [
    {
      date: new Date(now.getTime() - 86400000).toISOString(),
      timestamp: new Date(now.getTime() - 86400000).toISOString(),
      message: 'Bulk API usage (15 in 1 hour)',
      severity: 'low',
      eventType: 'BulkApiRequest'
    }
  ];
  
  userActivities.set('002', user2);
  
  return userActivities;
}

// Main test function
async function testPdfGeneration() {
  try {
    console.log('Creating test data...');
    const userActivities = createTestData();
    
    console.log('Generating PDF report...');
    const outputPath = path.join(process.cwd(), 'output/reports', 'test-report.pdf');
    
    const result = await htmlReportGenerator.generateSecurityReport({
      userActivities,
      outputPath,
      reportOptions: {
        title: 'Test Security Report',
        dateRange: 'April 1-3, 2023',
        organization: 'Test Organization'
      }
    });
    
    console.log(`PDF report generated at: ${result}`);
    console.log('HTML debug version is also available in the same directory.');
  } catch (error) {
    console.error('Error generating report:', error);
  }
}

// Run the test
testPdfGeneration(); 