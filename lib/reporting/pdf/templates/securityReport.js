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
  
  // Add event type section with visualizations
  addEventTypeSection(doc, processedData, options);
  
  // Add geographical risk section
  addGeographicalRiskSection(doc, processedData, options);
  
  // Add detailed findings section
  addDetailedFindingsSection(doc, processedData, options);
  
  // Add per-user detailed sections
  addUserDetailedSections(doc, processedData, options);
  
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
  
  // Draw user risk heatmap
  drawUserRiskHeatmap(doc, data, doc.x, doc.y);
  
  // Move down for table
  doc.moveDown(12);
  
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
 * Draws a heatmap visualization of user risk distribution
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {number} x - X position
 * @param {number} y - Y position
 */
function drawUserRiskHeatmap(doc, data, x, y) {
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const cellSize = 30;
  const maxCellsPerRow = Math.floor(width / cellSize);
  const padding = 5;
  
  // Title for the heatmap
  doc.fontSize(14)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.text.dark)
     .text('User Risk Distribution Heatmap', x, y);
     
  doc.moveDown(0.5);
     
  // Sort users by risk score descending
  const sortedUsers = [...data.users].sort((a, b) => b.riskScore - a.riskScore);
  
  // Calculate how many rows we need
  const totalUsers = sortedUsers.length;
  const rows = Math.ceil(totalUsers / maxCellsPerRow);
  
  // Draw user "heat" cells
  sortedUsers.forEach((user, index) => {
    const row = Math.floor(index / maxCellsPerRow);
    const col = index % maxCellsPerRow;
    
    const cellX = x + (col * cellSize);
    const cellY = y + 25 + (row * cellSize);
    
    // Determine color based on risk level
    const riskColor = getRiskLevelColor(user.riskLevel);
    
    // Draw cell background
    doc.rect(cellX, cellY, cellSize - padding, cellSize - padding)
       .fillAndStroke(riskColor, 'white');
    
    // Draw user initials if we have a username
    if (user.username) {
      const initials = getUserInitials(user.username);
      
      // Use white text for dark backgrounds, black for light backgrounds
      const textColor = ['critical', 'high'].includes(user.riskLevel.toLowerCase()) ? 'white' : 'black';
      
      doc.fontSize(10)
         .font('Helvetica-Bold')
         .fillColor(textColor)
         .text(initials, cellX, cellY + 8, {
           width: cellSize - padding,
           align: 'center'
         });
    }
  });
  
  // Draw legend
  const legendY = y + 25 + (rows * cellSize) + 10;
  
  doc.fontSize(12)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.text.dark)
     .text('Risk Level:', x, legendY);
  
  const riskLevels = [
    { level: 'Critical', color: styleConfig.colors.risk.critical },
    { level: 'High', color: styleConfig.colors.risk.high },
    { level: 'Medium', color: styleConfig.colors.risk.medium },
    { level: 'Low', color: styleConfig.colors.risk.low },
    { level: 'None', color: styleConfig.colors.risk.none }
  ];
  
  let legendX = x + 80;
  
  riskLevels.forEach(risk => {
    // Draw color square
    doc.rect(legendX, legendY, 15, 15)
       .fill(risk.color);
    
    // Draw level text
    doc.fontSize(10)
       .font('Helvetica')
       .fillColor(styleConfig.colors.text.dark)
       .text(risk.level, legendX + 20, legendY + 3);
       
    legendX += 100;
  });
}

/**
 * Gets initials from a username
 * @param {string} username - Username or email
 * @returns {string} Initials (1-2 characters)
 */
function getUserInitials(username) {
  // For emails, get the part before the @
  const name = username.split('@')[0];
  
  // Split by common separators and get initials
  const parts = name.split(/[._-]/);
  
  if (parts.length > 1) {
    // Get first letters of first and last parts
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
  
  // Just return the first 1-2 characters
  return name.substring(0, 2).toUpperCase();
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
    data.summary.criticalWarnings || 0,
    data.summary.highWarnings || 0,
    data.summary.mediumWarnings || 0,
    data.summary.lowWarnings || 0
  ];
  
  // Create chart data
  const chartData = {
    labels,
    values
  };
  
  // Draw the chart
  SimpleChartGenerator.drawPieChart(doc, x + 250, y + 150, chartData, {
    title: 'Risk Severity Distribution',
    radius: 100,
    colors: [styleConfig.colors.risk.critical, styleConfig.colors.risk.high, styleConfig.colors.risk.medium, styleConfig.colors.risk.low]
  });
  
  // Draw a gauge chart for overall risk level
  drawRiskGauge(doc, data, x + 50, y + 150);
}

/**
 * Draws a gauge chart for risk level
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {number} x - X position
 * @param {number} y - Y position
 */
function drawRiskGauge(doc, data, x, y) {
  const radius = 80;
  const centerX = x;
  const centerY = y;
  
  // Calculate risk level numeric value (0-100)
  let riskValue = 0;
  const riskLevel = determineOverallRiskLevel(data.summary);
  
  switch(riskLevel) {
    case 'Critical': riskValue = 90; break;
    case 'High': riskValue = 70; break;
    case 'Medium': riskValue = 50; break;
    case 'Low': riskValue = 30; break;
    case 'Minimal': riskValue = 10; break;
  }
  
  // Draw gauge background (semi-circle)
  doc.save();
  doc.strokeColor('#ccc')
     .lineWidth(2)
     .arc(centerX, centerY, radius, Math.PI, 2 * Math.PI, false)
     .stroke();
  doc.restore();
  
  // Draw colored sections of gauge
  const sections = [
    { color: styleConfig.colors.risk.none, end: 0.2 },
    { color: styleConfig.colors.risk.low, end: 0.4 },
    { color: styleConfig.colors.risk.medium, end: 0.6 },
    { color: styleConfig.colors.risk.high, end: 0.8 },
    { color: styleConfig.colors.risk.critical, end: 1.0 }
  ];
  
  sections.forEach((section, i) => {
    const startAngle = Math.PI + (i > 0 ? sections[i-1].end * Math.PI : 0);
    const endAngle = Math.PI + section.end * Math.PI;
    
    doc.save();
    doc.strokeColor(section.color)
       .lineWidth(20)
       .arc(centerX, centerY, radius, startAngle, endAngle, false)
       .stroke();
    doc.restore();
  });
  
  // Draw needle
  const needleAngle = Math.PI + (riskValue / 100) * Math.PI;
  const needleLength = radius - 10;
  
  doc.save();
  doc.strokeColor('#333')
     .lineWidth(3)
     .moveTo(centerX, centerY)
     .lineTo(
       centerX + needleLength * Math.cos(needleAngle),
       centerY + needleLength * Math.sin(needleAngle)
     )
     .stroke();
     
  // Draw center point of needle
  doc.fillColor('#333')
     .circle(centerX, centerY, 8)
     .fill();
  doc.restore();
  
  // Draw title and risk level
  doc.fontSize(14)
     .font('Helvetica-Bold')
     .fillColor('#333')
     .text('Overall Risk Level', centerX - 80, centerY + radius + 10, { width: 160, align: 'center' });
  
  const riskColor = getRiskLevelColor(riskLevel);
  doc.fontSize(18)
     .fillColor(riskColor)
     .text(riskLevel, centerX - 80, centerY + radius + 35, { width: 160, align: 'center' });
}

function drawTopUsersChart(doc, data, x, y, options = {}) {
  // Get top 5 users by risk score
  const topUsers = data.users
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
    width: 500,
    height: 200,
    colors: topUsers.map(user => getRiskLevelColor(user.riskLevel))
  });
  
  // Draw horizontal bar chart for event types
  const eventTypeData = getEventTypeData(data);
  drawEventTypeChart(doc, eventTypeData, x, y + 250);
}

/**
 * Aggregates event type data from all users
 * @param {Object} data - Report data
 * @returns {Object} Aggregated event type data
 */
function getEventTypeData(data) {
  const eventTypes = {};
  
  // Count events by type
  data.users.forEach(user => {
    (user.warnings || []).forEach(warning => {
      const eventType = warning.eventType || 'Unknown';
      if (!eventTypes[eventType]) {
        eventTypes[eventType] = 0;
      }
      eventTypes[eventType]++;
    });
  });
  
  // Convert to array and sort by count
  const eventTypeArray = Object.entries(eventTypes)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6); // Top 6 event types
  
  return {
    labels: eventTypeArray.map(et => et.name),
    values: eventTypeArray.map(et => et.count)
  };
}

/**
 * Draws a horizontal bar chart for event types
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Chart data
 * @param {number} x - X position
 * @param {number} y - Y position
 */
function drawEventTypeChart(doc, data, x, y) {
  const width = 500;
  const rowHeight = 30;
  const barHeight = 20;
  const maxBarWidth = 350;
  
  // Draw title
  doc.fontSize(14)
     .font('Helvetica-Bold')
     .fillColor('#333')
     .text('Security Events by Type', x, y, { width: width, align: 'left' });
  
  // Find maximum value for scaling
  const maxValue = Math.max(...data.values);
  
  // Draw each bar
  data.labels.forEach((label, i) => {
    const value = data.values[i];
    const barWidth = (value / maxValue) * maxBarWidth;
    const rowY = y + 30 + (i * rowHeight);
    
    // Draw label
    doc.fontSize(10)
       .font('Helvetica')
       .fillColor('#333')
       .text(label, x, rowY + 5, { width: 120 });
    
    // Calculate color based on index (darker to lighter)
    const hue = 200; // Blue
    const saturation = 80;
    const lightness = 40 + (i * 5); // Vary lightness
    const color = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
    
    // Draw bar
    doc.rect(x + 130, rowY, barWidth, barHeight)
       .fillColor(color)
       .fill();
    
    // Draw value
    doc.fontSize(10)
       .font('Helvetica-Bold')
       .fillColor('#333')
       .text(value.toString(), x + 130 + barWidth + 5, rowY + 5);
  });
}

/**
 * Adds detailed user sections, one for each high risk user
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
function addUserDetailedSections(doc, data, options = {}) {
  // Skip if no high risk users
  const highRiskUsers = data.users.filter(user => 
    user.riskLevel === 'critical' || user.riskLevel === 'high' || user.riskScore > 30
  );
  
  if (highRiskUsers.length === 0) {
    return;
  }
  
  // Add new page for user sections
  doc.addPage();
  
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('User Risk Analysis', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Introduction text
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica')
     .fillColor(styleConfig.colors.text.dark)
     .text('This section provides a detailed analysis of users with elevated risk scores. Each user profile includes specific risk factors, event history, and recommended actions.', {
       align: 'left'
     });
  
  doc.moveDown(1.5);
  
  // Add each user section
  highRiskUsers.forEach((user, index) => {
    // Add page break between users except for the first one
    if (index > 0) {
      doc.addPage();
    } else {
      // Just ensure enough space
      ensureSpace(doc, 300);
    }
    
    // User header with username and risk level
    doc.fontSize(styleConfig.fonts.header.size.h2)
       .font('Helvetica-Bold');
       
    // Color based on risk level
    const riskColor = getRiskLevelColor(user.riskLevel);
    doc.fillColor(riskColor)
       .text(`User Profile: ${user.username}`, { align: 'left' });
    
    // Add risk indicator box
    const riskBoxWidth = 150;
    const riskBoxHeight = 40;
    const riskBoxX = doc.page.width - doc.page.margins.right - riskBoxWidth;
    
    doc.rect(riskBoxX, doc.y - 30, riskBoxWidth, riskBoxHeight)
       .fillAndStroke(riskColor, riskColor);
       
    doc.fillColor('white')
       .fontSize(14)
       .text(`Risk Level: ${user.riskLevel.toUpperCase()}`, 
             riskBoxX + 10, 
             doc.y - 25, 
             { align: 'center', width: riskBoxWidth - 20 });
    
    // Reset position
    doc.y += 15;
    
    // Add horizontal line
    drawHorizontalLine(doc, doc.y, { color: styleConfig.colors.secondary, width: 0.5 });
    doc.moveDown(1);
    
    // Two-column layout for user stats
    const colWidth = (doc.page.width - doc.page.margins.left - doc.page.margins.right) / 2 - 10;
    
    // Left column - User stats overview
    doc.fontSize(styleConfig.fonts.header.size.h3)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.secondary)
       .text('User Activity Summary', { continued: false });
    
    doc.moveDown(0.5);
    
    // Create user stats in a clean box
    doc.rect(doc.x, doc.y, colWidth, 120)
       .fillAndStroke(styleConfig.colors.background.highlight, styleConfig.colors.table.border);
       
    const statsY = doc.y;
    doc.fontSize(styleConfig.fonts.body.size)
       .font('Helvetica');
       
    // Display user stats as key-value pairs
    const userStats = [
      { key: 'Risk Score:', value: formatNumber(user.riskScore) },
      { key: 'Critical Events:', value: formatNumber(user.criticalEvents) },
      { key: 'High Risk Events:', value: formatNumber(user.highRiskEvents) },
      { key: 'Login Count:', value: formatNumber(user.loginCount) },
      { key: 'Unique IPs:', value: formatNumber(user.uniqueIPs) },
      { key: 'Last Login:', value: user.lastLoginDate ? formatDate(user.lastLoginDate) : 'N/A' }
    ];
    
    userStats.forEach((stat, i) => {
      doc.fillColor(styleConfig.colors.text.dark)
         .font('Helvetica-Bold')
         .text(stat.key, doc.x + 10, statsY + 10 + (i * 18), { continued: true, width: 100 })
         .font('Helvetica')
         .text(` ${stat.value}`);
    });
    
    // Save position after left column
    const leftColEndY = doc.y + 110; // Add enough space to account for the box
    
    // Reset position for right column
    doc.x = doc.x + colWidth + 20;
    doc.y = statsY - 20;
    
    // Right column - Risk factors and visualizations
    doc.fontSize(styleConfig.fonts.header.size.h3)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.secondary)
       .text('Risk Score Components', { continued: false });
    
    doc.moveDown(0.5);
    
    // Create small doughnut chart showing risk factors
    const components = {
      labels: ['Login Pattern', 'Location', 'API Usage', 'Data Access'],
      values: [
        Math.floor(user.riskScore * 0.3), 
        Math.floor(user.riskScore * 0.25),
        Math.floor(user.riskScore * 0.25),
        Math.floor(user.riskScore * 0.2)
      ]
    };
    
    SimpleChartGenerator.drawPieChart(doc, doc.x + 100, doc.y + 60, components, {
      radius: 60,
      colors: [
        styleConfig.colors.risk.critical,
        styleConfig.colors.risk.high,
        styleConfig.colors.risk.medium,
        styleConfig.colors.risk.low
      ]
    });
    
    // Reset position for next section - use the maximum Y from either column
    doc.x = doc.page.margins.left;
    doc.y = Math.max(leftColEndY, doc.y + 110); // Add enough space after the chart
    
    // Warning timeline section
    ensureSpace(doc, 250);
    
    doc.fontSize(styleConfig.fonts.header.size.h3)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.secondary)
       .text('Security Event Timeline', { continued: false });
    
    doc.moveDown(0.5);
    
    // Sort warnings by date
    const userWarnings = [...(user.warnings || [])].sort((a, b) => {
      const dateA = a.date ? new Date(a.date) : new Date(0);
      const dateB = b.date ? new Date(b.date) : new Date(0);
      return dateB - dateA; // Most recent first
    });
    
    if (userWarnings.length > 0) {
      // Create horizontal timeline visualization
      drawEventTimeline(doc, userWarnings);
      
      // Add table of warnings after timeline
      doc.moveDown(1);
      
      renderTable(doc, {
        headers: ['Date', 'Event Type', 'Severity', 'Description'],
        rows: userWarnings.map(warning => [
          formatDate(warning.date),
          warning.eventType,
          warning.severity.toUpperCase(),
          warning.message
        ]),
        widths: [0.2, 0.2, 0.15, 0.45],
        zebra: true,
        cellStyles: {
          colorMap: {
            2: { // Severity column
              'CRITICAL': styleConfig.colors.risk.critical,
              'HIGH': styleConfig.colors.risk.high,
              'MEDIUM': styleConfig.colors.risk.medium,
              'LOW': styleConfig.colors.risk.low
            }
          }
        }
      }, { repeatHeader: true });
    } else {
      doc.fontSize(styleConfig.fonts.body.size)
         .font('Helvetica')
         .fillColor(styleConfig.colors.text.dark)
         .text('No security events recorded for this user.', { align: 'left' });
    }
    
    // Add recommended actions section
    ensureSpace(doc, 150);
    
    doc.fontSize(styleConfig.fonts.header.size.h3)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.secondary)
       .text('Recommended Actions', { continued: false });
    
    doc.moveDown(0.5);
    
    // Generate recommendations based on user's risk profile
    const recommendations = generateRecommendations(user);
    
    // Display each recommendation as bullet points
    doc.fontSize(styleConfig.fonts.body.size)
       .font('Helvetica')
       .fillColor(styleConfig.colors.text.dark);
       
    recommendations.forEach(recommendation => {
      doc.text(`• ${recommendation}`, { align: 'left' });
      doc.moveDown(0.5);
    });
  });
}

/**
 * Draws a visual timeline of security events
 * @param {PDFDocument} doc - PDF document
 * @param {Array} events - Array of security events
 */
function drawEventTimeline(doc, events) {
  const timelineWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const timelineHeight = 80;
  const timelineY = doc.y + 40;
  
  // Draw timeline line
  doc.strokeColor(styleConfig.colors.table.border)
     .lineWidth(2)
     .moveTo(doc.x, timelineY)
     .lineTo(doc.x + timelineWidth, timelineY)
     .stroke();
  
  // If no events, just draw empty timeline
  if (events.length === 0) {
    doc.y = timelineY + 40;
    return;
  }
  
  // Get date range
  const dates = events.map(e => new Date(e.date || 0));
  const minDate = new Date(Math.min(...dates));
  const maxDate = new Date(Math.max(...dates));
  
  // Add some padding to date range
  minDate.setDate(minDate.getDate() - 1);
  maxDate.setDate(maxDate.getDate() + 1);
  
  const dateRange = maxDate - minDate;
  
  // Plot events on timeline
  events.slice(0, 10).forEach((event, i) => { // Limit to 10 events on timeline
    const eventDate = new Date(event.date || 0);
    const position = (eventDate - minDate) / dateRange;
    const x = doc.x + (timelineWidth * position);
    
    // Draw dot for event, color by severity
    const dotColor = getSeverityColor(event.severity);
    const dotSize = event.severity === 'critical' ? 10 : 
                    event.severity === 'high' ? 8 : 6;
                    
    doc.circle(x, timelineY, dotSize)
       .fillAndStroke(dotColor, dotColor);
    
    // Draw date label above line
    doc.fontSize(8)
       .fillColor(styleConfig.colors.text.dark)
       .text(formatDate(event.date, true), 
             x - 25, 
             timelineY - 25, 
             { width: 50, align: 'center' });
    
    // Draw event type label below line
    doc.fontSize(8)
       .fillColor(dotColor)
       .text(event.eventType || 'Unknown', 
             x - 30, 
             timelineY + 10, 
             { width: 60, align: 'center' });
  });
  
  // Update Y position for next element
  doc.y = timelineY + 40;
}

/**
 * Generates recommendations based on user risk profile
 * @param {Object} user - User data
 * @returns {Array} Array of recommendation strings
 */
function generateRecommendations(user) {
  const recommendations = [];
  
  // Basic recommendations regardless of risk profile
  recommendations.push('Verify this user\'s identity and account access policies.');
  
  // Add risk-specific recommendations
  if (user.riskLevel === 'critical') {
    recommendations.push('Immediately require password reset and multi-factor authentication.');
    recommendations.push('Consider temporary account suspension until security review is complete.');
    recommendations.push('Perform forensic analysis of all account activities in the past 30 days.');
  } else if (user.riskLevel === 'high') {
    recommendations.push('Require password reset within the next 24 hours.');
    recommendations.push('Enable enhanced monitoring for this account for the next 14 days.');
    recommendations.push('Review IP restrictions and login hour limitations for this user.');
  }
  
  // Add event-specific recommendations
  if (hasEventType(user.warnings, 'LocationChange')) {
    recommendations.push('Investigate multiple geographic location logins to determine if credential sharing is occurring.');
  }
  
  if (hasEventType(user.warnings, 'InternationalLogin')) {
    recommendations.push('Verify if international travel was authorized for this user.');
    recommendations.push('Consider implementing geo-fencing restrictions if appropriate.');
  }
  
  if (hasEventType(user.warnings, 'ApiAnomalyEventStore')) {
    recommendations.push('Review API usage patterns and implement appropriate rate limiting.');
  }
  
  return recommendations;
}

/**
 * Helper to check if user has specific event type
 * @param {Array} warnings - User warnings
 * @param {string} eventType - Event type to check
 * @returns {boolean} Whether event type exists
 */
function hasEventType(warnings, eventType) {
  return warnings && warnings.some(w => w.eventType === eventType);
}

/**
 * Gets color for risk level
 * @param {string} riskLevel - Risk level
 * @returns {string} Color hex code
 */
function getRiskLevelColor(riskLevel) {
  switch(riskLevel.toLowerCase()) {
    case 'critical': return styleConfig.colors.risk.critical;
    case 'high': return styleConfig.colors.risk.high;
    case 'medium': return styleConfig.colors.risk.medium;
    case 'low': return styleConfig.colors.risk.low;
    default: return styleConfig.colors.risk.none;
  }
}

/**
 * Gets color for severity level
 * @param {string} severity - Severity level
 * @returns {string} Color hex code
 */
function getSeverityColor(severity) {
  switch(severity.toLowerCase()) {
    case 'critical': return styleConfig.colors.risk.critical;
    case 'high': return styleConfig.colors.risk.high;
    case 'medium': return styleConfig.colors.risk.medium;
    case 'low': return styleConfig.colors.risk.low;
    default: return styleConfig.colors.text.light;
  }
}

/**
 * Adds geographical risk section with world map
 * @param {PDFDocument} doc - PDF document
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 */
function addGeographicalRiskSection(doc, data, options = {}) {
  // Add new page for geographical analysis
  doc.addPage();
  
  // Section header
  doc.fontSize(styleConfig.fonts.header.size.h1)
     .font('Helvetica-Bold')
     .fillColor(styleConfig.colors.primary)
     .text('Geographic Risk Analysis', { align: 'left' });
  
  // Add horizontal line
  drawHorizontalLine(doc, doc.y + 5, { color: styleConfig.colors.primary, width: 1 });
  doc.moveDown(1);
  
  // Introduction text
  doc.fontSize(styleConfig.fonts.body.size)
     .font('Helvetica')
     .fillColor(styleConfig.colors.text.dark)
     .text('This section shows a geographical distribution of login activity. International login events and rapid location changes may indicate compromised credentials or unauthorized access.', {
       align: 'left'
     });
  
  doc.moveDown(1);
  
  // Extract location data from user activities
  const locationData = extractLocationData(data);
  
  // Draw map visualization
  const mapHeight = SimpleChartGenerator.drawGeoRiskMap(doc, doc.x, doc.y, locationData, {
    title: 'Login Locations by Risk Level',
    width: 500,
    height: 300,
    riskColors: {
      'critical': styleConfig.colors.risk.critical,
      'high': styleConfig.colors.risk.high,
      'medium': styleConfig.colors.risk.medium,
      'low': styleConfig.colors.risk.low,
      'none': styleConfig.colors.risk.none
    }
  });
  
  // Move down after map
  doc.y += mapHeight;
  
  // Add international login warnings table
  doc.moveDown(1);
  
  // Filter warnings for location-based events
  const locationWarnings = [];
  
  data.users.forEach(user => {
    (user.warnings || []).forEach(warning => {
      if (warning.eventType === 'LocationChange' || warning.eventType === 'InternationalLogin') {
        locationWarnings.push({
          username: user.username,
          ...warning
        });
      }
    });
  });
  
  // Sort by severity
  locationWarnings.sort((a, b) => {
    const severityRank = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0 };
    return severityRank[b.severity] - severityRank[a.severity];
  });
  
  if (locationWarnings.length > 0) {
    // Header for table
    doc.fontSize(styleConfig.fonts.header.size.h2)
       .font('Helvetica-Bold')
       .fillColor(styleConfig.colors.secondary)
       .text('Location-Based Security Events', { align: 'left' });
    
    doc.moveDown(0.5);
    
    // Prepare table data
    const tableHeaders = ['User', 'Event Type', 'Location', 'Date', 'Severity'];
    const tableRows = locationWarnings.map(warning => [
      warning.username,
      warning.eventType,
      warning.context?.curr_location || warning.context?.location || 'Unknown',
      formatDate(warning.date, true),
      warning.severity.toUpperCase()
    ]);
    
    // Configure color coding for risk levels
    const cellStyles = {
      colorMap: {
        4: { // Severity column (0-indexed)
          'CRITICAL': styleConfig.colors.risk.critical,
          'HIGH': styleConfig.colors.risk.high,
          'MEDIUM': styleConfig.colors.risk.medium,
          'LOW': styleConfig.colors.risk.low
        }
      }
    };
    
    // Render the table
    renderTable(doc, {
      headers: tableHeaders,
      rows: tableRows.slice(0, 10), // Show only top 10
      widths: [0.25, 0.2, 0.25, 0.15, 0.15], // Proportional widths
      cellStyles,
      zebra: true
    }, { repeatHeader: true });
    
    // Add note if more warnings exist
    if (locationWarnings.length > 10) {
      doc.moveDown(0.5);
      doc.fontSize(styleConfig.fonts.body.size)
         .font('Helvetica-Italic')
         .fillColor(styleConfig.colors.text.light)
         .text(`+ ${locationWarnings.length - 10} more location-based events not shown.`, { align: 'right' });
    }
  } else {
    // No location warnings
    doc.fontSize(styleConfig.fonts.body.size)
       .font('Helvetica-Italic')
       .fillColor(styleConfig.colors.text.medium)
       .text('No location-based security events were detected in this analysis period.', { align: 'center' });
  }
}

/**
 * Extracts location data from user warnings
 * @param {Object} data - Report data
 * @returns {Array} Array of location data objects
 */
function extractLocationData(data) {
  const locations = [];
  const locationCounts = {};
  
  // Process all users
  data.users.forEach(user => {
    (user.warnings || []).forEach(warning => {
      // Check for location data in warnings
      if (warning.eventType === 'LocationChange' || warning.eventType === 'InternationalLogin') {
        let locationName;
        
        if (warning.context) {
          // For location change events, use current location
          locationName = warning.context.curr_location || warning.context.location;
        }
        
        if (!locationName) {
          // Skip if no location information
          return;
        }
        
        // Keep track of unique locations and their risk levels
        if (!locationCounts[locationName]) {
          locationCounts[locationName] = {
            count: 0,
            riskLevel: warning.severity || 'low'
          };
        }
        
        locationCounts[locationName].count++;
        
        // Upgrade risk level if higher severity found
        const riskRanking = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0 };
        if (riskRanking[warning.severity] > riskRanking[locationCounts[locationName].riskLevel]) {
          locationCounts[locationName].riskLevel = warning.severity;
        }
      }
    });
  });
  
  // Convert to array format
  Object.entries(locationCounts).forEach(([location, data]) => {
    locations.push({
      location,
      count: data.count,
      riskLevel: data.riskLevel
    });
  });
  
  return locations;
}

module.exports = createSecurityReport; 