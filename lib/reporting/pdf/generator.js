/**
 * PDF Report Generator
 * Main module for generating PDF reports
 */

const fs = require('fs');
const path = require('path');
const createSecurityReport = require('./templates/securityReport');
const dataTransformer = require('./utils/dataTransformer');

/**
 * Generates a security report PDF
 * @param {Object} options - Report generation options
 * @param {Map<string, Object>} options.userActivities - User activity data
 * @param {string} options.outputPath - Path for the generated PDF
 * @param {Object} options.reportOptions - Additional report options
 * @returns {Promise<string>} Path to the generated PDF file
 */
async function generateSecurityReport(options) {
  try {
    // Validate required options
    if (!options.userActivities) {
      throw new Error('User activities data is required');
    }
    
    const outputPath = options.outputPath || path.join(process.cwd(), 'security-report.pdf');
    
    // Transform user data into format suitable for the report
    const reportData = dataTransformer.transformUserData(options.userActivities);
    
    // Generate report using the security report template
    const doc = createSecurityReport(reportData, {
      title: options.reportOptions?.title || 'Security Analysis Report',
      dateRange: options.reportOptions?.dateRange,
      organization: options.reportOptions?.organization,
      scanDate: options.reportOptions?.scanDate || new Date(),
      logoPath: options.reportOptions?.logoPath,
      includeAppendix: options.reportOptions?.includeAppendix !== false,
      includeAllWarnings: options.reportOptions?.includeAllWarnings !== false,
      contactInfo: options.reportOptions?.contactInfo
    });
    
    // Create output directory if it doesn't exist
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Write PDF to file
    const writeStream = fs.createWriteStream(outputPath);
    doc.pipe(writeStream);
    
    // Return promise that resolves when PDF is written
    return new Promise((resolve, reject) => {
      writeStream.on('finish', () => resolve(outputPath));
      writeStream.on('error', reject);
    });
  } catch (error) {
    throw new Error(`Failed to generate security report: ${error.message}`);
  }
}

/**
 * Gets supported report options
 * @returns {Object} Description of supported report options
 */
function getSupportedReportOptions() {
  return {
    title: 'Report title (string)',
    dateRange: 'Date range covered by the report (string)',
    organization: 'Organization name (string)',
    scanDate: 'Date when the scan was performed (Date or string)',
    logoPath: 'Path to logo image (string)',
    includeAppendix: 'Whether to include appendix section (boolean)',
    includeAllWarnings: 'Whether to include all warning levels (boolean)',
    contactInfo: 'Contact information to include in the report (string)'
  };
}

/**
 * Checks if PDF generation is available
 * @returns {boolean} Whether PDF generation is available
 */
function isPdfGenerationAvailable() {
  try {
    // Check for required dependencies
    require('pdfkit');
    return true;
  } catch (error) {
    return false;
  }
}

module.exports = {
  generateSecurityReport,
  getSupportedReportOptions,
  isPdfGenerationAvailable
}; 