/**
 * Security Report PDF Template
 * Defines layout and structure for security reports
 */

const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

const styleConfig = require('../utils/styleConfig');
const { renderTable } = require('../components/tableRenderer');
const SimpleChartGenerator = require('../components/chartGenerator');
const { 
  wrapText, 
  formatDate, 
  loadImage, 
  formatNumber,
  drawHorizontalLine,
  ensureSpace
} = require('../utils/pdfHelpers');

/**
 * Generates a security report PDF
 * @param {Object} data - Report data
 * @param {Object} options - Report generation options
 * @returns {PDFDocument} Generated PDF document
 */
function createSecurityReport(data, options = {}) {
  // Create new PDF document with default built-in fonts
  const doc = new PDFDocument({
    size: styleConfig.page.size,
    margins: styleConfig.page.margins,
    info: {
      Title: options.title || 'Security Analysis Report',
      Author: 'DataDragon',
      Subject: 'Security Analysis'
    }
  });

  // Set default fonts - using built-in fonts only
  doc.font('Helvetica');
  
  // Preprocess data for the report
  const processedData = preprocessReportData(data);
  
  // Title page
  addCoverPage(doc, processedData, options);
  
  // Executive summary
  addExecutiveSummary(doc, processedData, options);
  
  // Risk analysis
  addRiskDistributionSection(doc, processedData, options);
  
  // User activity details
  addHighRiskUsersSection(doc, processedData, options);
  
  // Appendix with detailed warnings
  if (options.includeAppendix !== false) {
    addAppendixSection(doc, processedData, options);
  }
  
  // Finalize PDF
  doc.end();
  
  return doc;
}

/**
 * Preprocesses input data for the report
 * @param {Object} data - Raw data from the transformer
 * @returns {Object} Processed data ready for reporting
 */
function preprocessReportData(data) {
  // Create a copy to avoid modifying the original
  const processed = { ...data };
  
  // Ensure the summary object exists
  processed.summary = processed.summary || {};
  
  // Calculate warning counts by severity if not provided
  if (!processed.summary.criticalWarnings || !processed.summary.highWarnings) {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    
    // Count warnings from users
    if (processed.users) {
      Object.values(processed.users).forEach(user => {
        if (user.riskProfile) {
          criticalCount += user.riskProfile.critical || 0;
          highCount += user.riskProfile.high || 0;
          mediumCount += user.riskProfile.medium || 0;
          lowCount += user.riskProfile.low || 0;
        }
      });
    }
    
    // Update summary with counts
    processed.summary.criticalWarnings = criticalCount;
    processed.summary.highWarnings = highCount;
    processed.summary.mediumWarnings = mediumCount;
    processed.summary.lowWarnings = lowCount;
    processed.summary.totalWarnings = criticalCount + highCount + mediumCount + lowCount;
  }
  
  // Calculate high risk users count if not provided
  if (!processed.summary.highRiskUsers) {
    let highRiskCount = 0;
    
    if (processed.users) {
      highRiskCount = Object.values(processed.users).filter(user => 
        user.riskLevel === 'critical' || user.riskLevel === 'high'
      ).length;
    }
    
    processed.summary.highRiskUsers = highRiskCount;
  }
  
  return processed;
}

/**
 * Creates the cover page
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
function addCoverPage(doc, data, options) {
  const centerX = doc.page.width / 2;
  
  // Add logo if available
  const logoPath = options.logoPath || path.join(__dirname, '../../../../assets/logo.png');
  const logo = loadImage(logoPath);
  
  if (logo) {
    doc.image(logo, centerX - 100, 100, {
      width: 200,
      align: 'center'
    });
  }
  
  // Add title
  doc.fontSize(styleConfig.fonts.header.size.title)
     .font(`Helvetica-Bold`)
     .fillColor(styleConfig.colors.primary)
     .text(options.title || 'Security Analysis Report', 
           centerX - 200, 
           logo ? 250 : 150, 
           { width: 400, align: 'center' });
  
  // Add subtitle
  doc.fontSize(styleConfig.fonts.header.size.h2)
     .fillColor(styleConfig.colors.secondary)
     .text('Salesforce EventLogFile Analysis', 
           centerX - 200, 
           doc.y + styleConfig.spacing.md, 
           { width: 400, align: 'center' });
  
  // Add date range
  const dateRange = options.dateRange || `Generated on ${formatDate(new Date())}`;
  doc.fontSize(styleConfig.fonts.header.size.h3)
     .fillColor(styleConfig.colors.text.medium)
     .text(dateRange, 
           centerX - 200, 
           doc.y + styleConfig.spacing.lg, 
           { width: 400, align: 'center' });
  
  // Add organization info if available
  if (options.organization) {
    doc.fontSize(styleConfig.fonts.body.size)
       .fillColor(styleConfig.colors.text.dark)
       .text(`Organization: ${options.organization}`, 
             centerX - 200, 
             doc.y + styleConfig.spacing.lg, 
             { width: 400, align: 'center' });
  }
  
  // Add confidentiality notice
  doc.fontSize(styleConfig.fonts.body.size)
     .fillColor(styleConfig.colors.text.dark)
     .text('CONFIDENTIAL SECURITY DOCUMENT', 
           centerX - 200, 
           doc.page.height - 180, 
           { width: 400, align: 'center' });
  
  // Add footer
  doc.fontSize(styleConfig.fonts.body.size - 1)
     .fillColor(styleConfig.colors.text.light)
     .text('This report contains sensitive security information. Handle with care.', 
           centerX - 200, 
           doc.page.height - 160, 
           { width: 400, align: 'center' });
  
  // Add new page for content
  doc.addPage();
}

/**
 * Adds executive summary section
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
async function addExecutiveSummary(doc, data, options = {}) {
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Executive Summary', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Data for summary table
  const summaryData = data.summary || {};
  
  // Create summary box
  doc.rect(doc.x, 
           doc.y, 
           doc.page.width - doc.page.margins.left - doc.page.margins.right, 
           150)
     .fillAndStroke(styleConfig.colors.background.highlight, styleConfig.colors.primary);
  
  // Reset position for content
  const boxStartY = doc.y;
  
  // Key findings
  doc.y = boxStartY + styleConfig.spacing.md;
  doc.x = doc.page.margins.left + styleConfig.spacing.md;
  
  doc.fontSize(styleConfig.fonts.header.size.h2)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Key Findings:', { continued: true })
     .font('Helvetica')
     .text(' ' + formatDate(new Date()));
  
  doc.moveDown(0.5);
  
  // Stats in bold
  const riskSummary = [
    `${formatNumber(summaryData.totalWarnings || 0)} security issues detected`,
    `${formatNumber(summaryData.highRiskUsers || 0)} high-risk users identified`,
    `${formatNumber(summaryData.criticalWarnings || 0)} critical warnings`
  ];
  
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.text.dark);
     
  riskSummary.forEach((item, i) => {
    // Determine color based on value
    let valueColor = styleConfig.colors.text.dark;
    
    if (i === 0 && summaryData.totalWarnings > 50) {
      valueColor = styleConfig.colors.risk.critical;
    } else if (i === 1 && summaryData.highRiskUsers > 5) {
      valueColor = styleConfig.colors.risk.high;
    } else if (i === 2 && summaryData.criticalWarnings > 10) {
      valueColor = styleConfig.colors.risk.critical;
    }
    
    doc.fillColor(valueColor)
       .text(`• ${item}`);
  });
  
  // Overall risk level
  doc.moveDown(1);
  
  const riskLevel = determineOverallRiskLevel(summaryData);
  
  doc.fontSize(styleConfig.fonts.header.size.h3)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.text.dark)
     .text('Overall Risk Assessment:', { continued: true });
     
  // Set color based on risk level
  const riskColors = {
    'Critical': styleConfig.colors.risk.critical,
    'High': styleConfig.colors.risk.high,
    'Medium': styleConfig.colors.risk.medium,
    'Low': styleConfig.colors.risk.low,
    'Minimal': styleConfig.colors.risk.none
  };
  
  doc.fillColor(riskColors[riskLevel] || styleConfig.colors.text.dark)
     .text(` ${riskLevel}`);
  
  // Next section
  doc.y = boxStartY + 150 + styleConfig.spacing.md;
  doc.moveDown(1);
}

/**
 * Adds risk distribution section with charts
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
async function addRiskDistributionSection(doc, data, options) {
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Risk Distribution', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  try {
    // Draw risk distribution chart
    drawRiskDistributionChart(doc, data, doc.x, doc.y);
    
    // Add text explanation of the charts
    doc.fontSize(styleConfig.fonts.body.size)
       .font('Helvetica')
       .fillColor(styleConfig.colors.text.dark)
       .text('The chart above shows the distribution of security warnings by severity level. Critical and high severity issues require immediate attention.', {
         align: 'center',
         width: 400
       });
    
    doc.moveDown(2);
  } catch (error) {
    // In case chart generation fails, provide text summary instead
    doc.fontSize(styleConfig.fonts.body.size)
       .font('Helvetica')
       .fillColor(styleConfig.colors.text.dark)
       .text(`Security warnings by severity: Critical: ${data.summary.criticalWarnings || 0}, High: ${data.summary.highWarnings || 0}, Medium: ${data.summary.mediumWarnings || 0}, Low: ${data.summary.lowWarnings || 0}`, {
         align: 'left'
       });
    
    doc.moveDown(1);
  }
}

/**
 * Adds high risk users section
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
function addHighRiskUsersSection(doc, data, options) {
  // Skip if no users or all users have no risk
  const highRiskUsers = (data.users || []).filter(user => user.riskScore > 30);
  
  if (highRiskUsers.length === 0) {
    return;
  }
  
  // Ensure enough space or add new page
  ensureSpace(doc, 300);
  
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('High Risk Users', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Create table of high risk users
  const tableHeaders = ['Username', 'Risk Score', 'Risk Level', 'Critical Events', 'Last Login'];
  const tableRows = highRiskUsers.slice(0, 10).map(user => [
    user.username,
    user.riskScore,
    user.riskLevel.toUpperCase(),
    user.criticalEvents,
    formatDate(user.lastLoginDate)
  ]);
  
  // Configure color coding for risk levels
  const cellStyles = {
    colorMap: {
      2: { // Risk Level column (0-indexed)
        'CRITICAL': styleConfig.colors.risk.critical,
        'HIGH': styleConfig.colors.risk.high,
        'MEDIUM': styleConfig.colors.risk.medium,
        'LOW': styleConfig.colors.risk.low,
        'NONE': styleConfig.colors.risk.none
      }
    }
  };
  
  // Render the table
  renderTable(doc, {
    headers: tableHeaders,
    rows: tableRows,
    widths: [0.3, 0.15, 0.2, 0.15, 0.2], // Proportional widths
    cellStyles,
    zebra: true
  }, { repeatHeader: true });
  
  doc.moveDown(1);
}

/**
 * Adds event type section showing warnings by type
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
async function addEventTypeSection(doc, data, options) {
  // Ensure enough space or add new page
  ensureSpace(doc, 400);
  
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Security Events by Type', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Collect and aggregate warnings by event type
  const eventTypes = {};
  
  (data.users || []).forEach(user => {
    (user.warnings || []).forEach(warning => {
      const eventType = warning.eventType || 'Unknown';
      if (!eventTypes[eventType]) {
        eventTypes[eventType] = { count: 0, severity: {} };
      }
      
      // Count warning
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
  const eventTypeArray = Object.entries(eventTypes)
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.count - a.count);
  
  try {
    // Draw top users chart
    drawTopUsersChart(doc, data, doc.x, doc.y);
  } catch (error) {
    // If chart generation fails, show as table instead
    const tableHeaders = ['Event Type', 'Count', 'Critical', 'High', 'Medium', 'Low'];
    const tableRows = eventTypeArray.slice(0, 10).map(type => [
      type.name,
      type.count,
      type.severity.critical || 0,
      type.severity.high || 0,
      type.severity.medium || 0,
      type.severity.low || 0
    ]);
    
    renderTable(doc, {
      headers: tableHeaders,
      rows: tableRows,
      zebra: true
    }, { repeatHeader: true });
  }
  
  // Add description text
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica')
     .fillColor(styleConfig.colors.text.dark)
     .text('The chart above shows the most frequent security event types detected. Events like LocationChange and InternationalLogin require immediate investigation.', {
       align: 'left',
       width: 500
     });
  
  doc.moveDown(2);
}

/**
 * Adds detailed findings section with comprehensive tables
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
function addDetailedFindingsSection(doc, data, options) {
  // Add new page for detailed findings
  doc.addPage();
  
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Detailed Security Findings', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Introduction text
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica')
     .fillColor(styleConfig.colors.text.dark)
     .text('This section contains detailed security findings organized by severity level. Each finding includes specific information about the security event, affected user, and timestamp.', {
       align: 'left'
     });
  
  doc.moveDown(1.5);
  
  // Group all warnings by severity
  const warningsBySeverity = {
    critical: [],
    high: [],
    medium: [],
    low: []
  };
  
  (data.users || []).forEach(user => {
    (user.warnings || []).forEach(warning => {
      const severity = warning.severity || 'low';
      if (!warningsBySeverity[severity]) {
        warningsBySeverity[severity] = [];
      }
      
      warningsBySeverity[severity].push({
        username: user.username,
        ...warning
      });
    });
  });
  
  // Sort warnings by date (most recent first)
  Object.keys(warningsBySeverity).forEach(severity => {
    warningsBySeverity[severity].sort((a, b) => {
      const dateA = a.date ? new Date(a.date) : new Date(0);
      const dateB = b.date ? new Date(b.date) : new Date(0);
      return dateB - dateA;
    });
  });
  
  // Display critical warnings
  if (warningsBySeverity.critical.length > 0) {
    // Critical warnings header
    doc.fontSize(styleConfig.fonts.header.size.h2)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.risk.critical)
       .text('Critical Warnings', { align: 'left' });
    
    doc.moveDown(0.5);
    
    // Critical warnings table
    const tableHeaders = ['User', 'Date', 'Event Type', 'Warning'];
    const tableRows = warningsBySeverity.critical.map(warning => [
      warning.username,
      formatDate(warning.date, true),
      warning.eventType || 'Unknown',
      warning.message
    ]);
    
    renderTable(doc, {
      headers: tableHeaders,
      rows: tableRows,
      widths: [0.2, 0.15, 0.15, 0.5], // Proportional widths
      zebra: true,
      truncate: { 3: 100 } // Truncate warning message if too long
    }, { 
      repeatHeader: true
    });
    
    doc.moveDown(1.5);
  }
  
  // Display high warnings
  if (warningsBySeverity.high.length > 0) {
    // Check if we need a new page
    ensureSpace(doc, 200);
    
    // High warnings header
    doc.fontSize(styleConfig.fonts.header.size.h2)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.risk.high)
       .text('High Severity Warnings', { align: 'left' });
    
    doc.moveDown(0.5);
    
    // High warnings table
    const tableHeaders = ['User', 'Date', 'Event Type', 'Warning'];
    const tableRows = warningsBySeverity.high.map(warning => [
      warning.username,
      formatDate(warning.date, true),
      warning.eventType || 'Unknown',
      warning.message
    ]);
    
    renderTable(doc, {
      headers: tableHeaders,
      rows: tableRows,
      widths: [0.2, 0.15, 0.15, 0.5], // Proportional widths
      zebra: true,
      truncate: { 3: 100 } // Truncate warning message if too long
    }, { 
      repeatHeader: true
    });
    
    doc.moveDown(1.5);
  }
  
  // Display medium and low warnings (combined if many warnings)
  const remainingWarnings = [...warningsBySeverity.medium, ...warningsBySeverity.low];
  
  if (remainingWarnings.length > 0 && options.includeAllWarnings) {
    // Check if we need a new page
    ensureSpace(doc, 200);
    
    // Remaining warnings header
    doc.fontSize(styleConfig.fonts.header.size.h2)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.risk.medium)
       .text('Medium and Low Severity Warnings', { align: 'left' });
    
    doc.moveDown(0.5);
    
    // Remaining warnings table
    const tableHeaders = ['User', 'Date', 'Severity', 'Event Type', 'Warning'];
    const tableRows = remainingWarnings
      .sort((a, b) => {
        // Sort by severity then date
        if (a.severity !== b.severity) {
          return a.severity === 'medium' ? -1 : 1;
        }
        
        const dateA = a.date ? new Date(a.date) : new Date(0);
        const dateB = b.date ? new Date(b.date) : new Date(0);
        return dateB - dateA;
      })
      .map(warning => [
        warning.username,
        formatDate(warning.date, true),
        warning.severity.toUpperCase(),
        warning.eventType || 'Unknown',
        warning.message
      ]);
    
    renderTable(doc, {
      headers: tableHeaders,
      rows: tableRows,
      widths: [0.15, 0.15, 0.1, 0.15, 0.45], // Proportional widths
      zebra: true,
      truncate: { 4: 100 } // Truncate warning message if too long
    }, { 
      repeatHeader: true
    });
    
    doc.moveDown(1.5);
  }
}

/**
 * Adds appendix section with additional information
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
function addAppendixSection(doc, data, options) {
  // Add new page for appendix
  doc.addPage();
  
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Appendix', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Add information about how the report was generated
  doc.fontSize(styleConfig.fonts.header.size.h2)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.secondary)
     .text('About This Report', { align: 'left' });
  
  doc.moveDown(0.5);
  
  // Report generation details
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica')
     .fillColor(styleConfig.colors.text.dark)
     .text('This security report was generated by DataDragon, a security monitoring tool for Salesforce EventLogFiles. The report analyzes login patterns, user behaviors, and suspicious activities to identify potential security risks.', {
       align: 'left'
     });
  
  doc.moveDown(1);
  
  // Add information about event types
  doc.fontSize(styleConfig.fonts.header.size.h2)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.secondary)
     .text('Event Type Descriptions', { align: 'left' });
  
  doc.moveDown(0.5);
  
  // Event type descriptions
  const eventTypeDescriptions = [
    {
      type: 'LocationChange',
      description: 'Detected when a user logs in from multiple geographic locations within a short time period, which may indicate compromised credentials or account sharing.'
    },
    {
      type: 'InternationalLogin',
      description: 'Login detected from a non-US location, which may represent increased risk if users are not expected to travel internationally.'
    },
    {
      type: 'LoginAs',
      description: 'Administrator impersonation of a user account. While a legitimate administrative function, it represents elevated access that should be monitored.'
    },
    {
      type: 'ApexExecution',
      description: 'Direct execution of Apex code, which can modify data and bypass normal application controls if misused.'
    },
    {
      type: 'ReportExport',
      description: 'Export of report data, which could be used for data exfiltration if misused.'
    },
    {
      type: 'ApiAnomalyEventStore',
      description: 'API usage patterns flagged as anomalous by Salesforce\'s internal security systems.'
    },
    {
      type: 'ContentDistribution',
      description: 'Creation of public links to internal documents, which may expose sensitive information.'
    }
  ];
  
  // Event type descriptions table
  const tableHeaders = ['Event Type', 'Description'];
  const tableRows = eventTypeDescriptions.map(item => [
    item.type,
    item.description
  ]);
  
  renderTable(doc, {
    headers: tableHeaders,
    rows: tableRows,
    widths: [0.25, 0.75], // Proportional widths
    zebra: true
  }, { 
    repeatHeader: true 
  });
  
  doc.moveDown(1);
  
  // Add contact information
  doc.fontSize(styleConfig.fonts.header.size.h2)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.secondary)
     .text('Contact Information', { align: 'left' });
  
  doc.moveDown(0.5);
  
  // Contact details
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica')
     .fillColor(styleConfig.colors.text.dark)
     .text('For questions about this report or to investigate security concerns further, please contact your security team.', {
       align: 'left'
     });
  
  if (options.contactInfo) {
    doc.moveDown(0.5);
    doc.text(options.contactInfo, { align: 'left' });
  }
}

/**
 * Determines overall risk level based on summary data
 * @param {Object} summary - Summary data
 * @returns {string} Risk level (Critical, High, Medium, Low, or Minimal)
 */
function determineOverallRiskLevel(summary) {
  // Check for critical conditions
  if (summary.criticalWarnings > 10 || summary.highRiskUsers > 5) {
    return 'Critical';
  }
  
  // Check for high risk conditions
  if (summary.criticalWarnings > 5 || summary.highWarnings > 10 || summary.highRiskUsers > 2) {
    return 'High';
  }
  
  // Check for medium risk conditions
  if (summary.criticalWarnings > 0 || summary.highWarnings > 5 || summary.highRiskUsers > 0) {
    return 'Medium';
  }
  
  // Check for low risk conditions
  if (summary.highWarnings > 0 || summary.mediumWarnings > 5) {
    return 'Low';
  }
  
  // Otherwise minimal risk
  return 'Minimal';
}

// Update chart rendering in the report
function drawRiskDistributionChart(doc, data, x, y, options = {}) {
  // Extract risk distribution data
  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const values = [
    data.summary.stats.riskDistribution.critical || 0,
    data.summary.stats.riskDistribution.high || 0,
    data.summary.stats.riskDistribution.medium || 0,
    data.summary.stats.riskDistribution.low || 0
  ];
  
  // Create chart data
  const chartData = {
    labels,
    values
  };
  
  // Draw the chart
  SimpleChartGenerator.drawPieChart(doc, x + 150, y + 120, chartData, {
    title: 'Risk Severity Distribution',
    radius: 100,
    colors: ['#FF0000', '#FF6600', '#FFCC00', '#3399FF']
  });
}

function drawTopUsersChart(doc, data, x, y, options = {}) {
  // Get top 5 users by risk score
  const topUsers = Object.values(data.users)
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);
    
  // Create chart data
  const chartData = {
    labels: topUsers.map(user => user.username.split('@')[0]),
    values: topUsers.map(user => user.riskScore)
  };
  
  // Draw the chart
  SimpleChartGenerator.drawBarChart(doc, x, y, chartData, {
    title: 'Top Users by Risk Score',
    width: 400,
    height: 200,
    colors: ['#0066CC']
  });
}

module.exports = createSecurityReport; 