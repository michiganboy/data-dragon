/**
 * HTML Report Generator
 * Generates HTML reports using EJS templates and converts to PDF using Puppeteer
 */

const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const puppeteer = require('puppeteer');
const utils = require('../../utils');
const dataTransformer = require('./utils/dataTransformer');

/**
 * Ensures output directories exist for report generation
 * @param {string} outputPath - Path where the report will be saved
 */
function ensureOutputDirectoryExists(outputPath) {
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    try {
      fs.mkdirSync(outputDir, { recursive: true });
    } catch (error) {
      throw new Error(`Failed to create output directory for report: ${error.message}`);
    }
  }
}

/**
 * Reads CSS and JavaScript files for the template
 * @returns {Object} Object containing CSS and JavaScript content
 */
function readAssets() {
  try {
    const cssPath = path.join(__dirname, 'css', 'report.css');
    const jsPath = path.join(__dirname, 'assets', 'report.js');
    
    const css = fs.readFileSync(cssPath, 'utf8');
    const js = fs.readFileSync(jsPath, 'utf8');
    
    return { css, js };
  } catch (error) {
    throw new Error(`Failed to read assets: ${error.message}`);
  }
}

/**
 * Generates an HTML security report using EJS templates
 * @param {Object} data - Report data
 * @param {Object} options - Report options
 * @returns {string} HTML content
 */
async function generateHtmlReport(data, options = {}) {
  try {
    // Main template file path
    const templatePath = path.join(__dirname, 'templates', 'report.ejs');
    
    // Read the template
    const template = fs.readFileSync(templatePath, 'utf8');
    
    // Read assets (CSS and JavaScript)
    const { css, js } = readAssets();
    
    // Prepare template data with defaults
    const templateData = {
      title: options.title || 'Security Analysis Report',
      dateRange: options.dateRange || `Generated on ${new Date().toLocaleDateString()}`,
      organization: options.organization || 'Your Organization',
      data: data,
      options: {
        includeAppendix: options.includeAppendix !== false,
        ...options
      }
    };
    
    // Render the template
    let html = ejs.render(template, templateData, {
      root: path.join(__dirname, 'templates'),
      views: [
        path.join(__dirname, 'components'),
        path.join(__dirname, 'templates')
      ]
    });
    
    // Inject CSS and JavaScript
    html = html.replace('/* CSS will be injected at runtime */', css);
    html = html.replace('/* JavaScript will be injected at runtime */', js);
    
    return html;
  } catch (error) {
    throw new Error(`Failed to generate HTML report: ${error.message}`);
  }
}

/**
 * Converts HTML content to PDF using Puppeteer
 * @param {string} html - HTML content
 * @param {string} outputPath - Path to save the PDF
 * @returns {Promise<string>} Path to the generated PDF
 */
async function convertHtmlToPdf(html, outputPath) {
  let browser = null;
  
  try {
    // Create temporary HTML file
    const tempHtmlPath = `${outputPath}.html`;
    fs.writeFileSync(tempHtmlPath, html);
    
    // Launch browser
    browser = await puppeteer.launch({
      headless: 'new'
    });
    
    // Create a new page
    const page = await browser.newPage();
    
    // Set content from file (better for large reports than direct content setting)
    await page.goto(`file://${tempHtmlPath}`, {
      waitUntil: 'networkidle0'
    });
    
    // Generate PDF
    await page.pdf({
      path: outputPath,
      format: 'A4',
      printBackground: true,
      margin: {
        top: '1cm',
        right: '1cm',
        bottom: '1cm',
        left: '1cm'
      }
    });
    
    // Remove temporary HTML file
    fs.unlinkSync(tempHtmlPath);
    
    return outputPath;
  } catch (error) {
    throw new Error(`Failed to convert HTML to PDF: ${error.message}`);
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

/**
 * Generates a security report in PDF format
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
    
    const outputPath = options.outputPath || path.join(process.cwd(), 'output/reports/security-report.pdf');
    
    // Ensure output directory exists
    ensureOutputDirectoryExists(outputPath);
    
    // Transform user data into format suitable for the report
    const reportData = dataTransformer.transformUserData(options.userActivities);
    
    // Generate HTML report
    const html = await generateHtmlReport(reportData, {
      title: options.reportOptions?.title || 'Security Analysis Report',
      dateRange: options.reportOptions?.dateRange,
      organization: options.reportOptions?.organization,
      scanDate: options.reportOptions?.scanDate || new Date(),
      logoPath: options.reportOptions?.logoPath,
      includeAppendix: options.reportOptions?.includeAppendix !== false,
      includeAllWarnings: options.reportOptions?.includeAllWarnings !== false,
      contactInfo: options.reportOptions?.contactInfo
    });
    
    // Save HTML for debugging if needed
    const htmlDebugPath = path.join(path.dirname(outputPath), 'debug-report.html');
    fs.writeFileSync(htmlDebugPath, html);
    
    // Convert HTML to PDF
    await convertHtmlToPdf(html, outputPath);
    
    return outputPath;
  } catch (error) {
    throw new Error(`Failed to generate security report: ${error.message}`);
  }
}

/**
 * Returns a list of supported report options
 * @returns {Object} Supported options with descriptions
 */
function getSupportedReportOptions() {
  return {
    title: 'Report title',
    dateRange: 'Date range for the analysis period',
    organization: 'Organization name',
    logoPath: 'Path to organization logo',
    includeAppendix: 'Include detailed appendix section',
    includeAllWarnings: 'Include all warnings regardless of severity',
    contactInfo: 'Contact information for the security team'
  };
}

/**
 * Checks if HTML-based PDF generation is available
 * @returns {boolean} Whether PDF generation is available
 */
function isPdfGenerationAvailable() {
  try {
    // Check for required dependencies
    require('ejs');
    require('puppeteer');
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