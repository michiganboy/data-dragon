/**
 * Test script for HTML report generation
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const htmlReportGenerator = require('./lib/reporting/html/generator');
const UserActivity = require('./models/userActivity');

// Main test function
async function testReportGeneration() {
  try {
    console.log('Loading mock data...');
    
    // Check if mock data exists, if not, suggest generating it
    const summaryJsonPath = path.join(process.cwd(), 'output', 'summary-report.json');
    if (!fs.existsSync(summaryJsonPath)) {
      console.log('Mock data not found. Please run "node generate-mock-data.js" first.');
      return;
    }
    
    // Load the mock data JSON
    const mockData = JSON.parse(fs.readFileSync(summaryJsonPath, 'utf8'));
    
    // Create UserActivity objects from the mock data
    const userActivities = new Map();
    
    if (mockData.userSummary) {
      // Create user activities from the summary
      Object.entries(mockData.userSummary).forEach(([username, userData]) => {
        const activity = new UserActivity(userData.userId, username);
        
        // Set properties
        activity.riskScore = userData.riskScore || 0;
        activity.riskLevel = userData.riskLevel || 'low';
        activity.criticalEvents = userData.criticalEvents || 0;
        activity.highRiskEvents = userData.highRiskEvents || 0;
        
        // Add warnings
        if (Array.isArray(userData.warnings)) {
          userData.warnings.forEach(warning => {
            activity.addWarning(warning);
          });
        }
        
        // Add anomalies if available
        if (Array.isArray(userData.anomalies)) {
          userData.anomalies = userData.anomalies;
          
          // Also convert to warnings for better visibility in the report
          userData.anomalies.forEach(anomaly => {
            const warningMessage = anomaly.description || 'Security anomaly detected';
            const warning = {
              date: anomaly.date,
              timestamp: anomaly.date,
              warning: warningMessage + (anomaly.details && anomaly.details.distanceDesc ? `: ${anomaly.details.distanceDesc}` : ''),
              severity: anomaly.severity || 'medium',
              eventType: 'SecurityAnomaly',
              context: anomaly.details || {}
            };
            activity.addWarning(warning);
          });
        }
        
        // Add login data if available
        if (userData.loginActivity) {
          if (userData.loginActivity.firstLogin && userData.loginActivity.lastLogin) {
            activity.loginDays = [
              userData.loginActivity.firstLogin,
              userData.loginActivity.lastLogin
            ];
          }
          
          // Add login times if available
          if (Array.isArray(userData.loginTimes)) {
            activity.loginTimes = userData.loginTimes.map(login => ({
              datetime: new Date(login.datetime),
              dayOfWeek: new Date(login.datetime).getDay(),
              hourOfDay: new Date(login.datetime).getHours(),
              sourceIp: login.sourceIp || '192.168.1.1',
              weekend: [0, 6].includes(new Date(login.datetime).getDay())
            }));
          }
        }
        
        userActivities.set(userData.userId, activity);
      });
    }
    
    console.log(`Creating report for ${userActivities.size} users...`);
    
    // Output path for the report
    const outputPath = path.join(process.cwd(), 'output/reports', 'test-report.html');
    
    const result = await htmlReportGenerator.generateSecurityReport({
      userActivities,
      outputPath,
      reportOptions: {
        title: 'Test Security Report',
        dateRange: 'Generated from mock data',
        organization: 'Test Organization'
      }
    });
    
    console.log('Report generated successfully:');
    console.log(`HTML report: ${result.htmlPath}`);
    console.log('To view the report, open the HTML file in your browser.');
    console.log('You can print it to PDF using your browser\'s print function.');
  } catch (error) {
    console.error('Error generating report:', error);
  }
}

// Run the test
testReportGeneration(); 