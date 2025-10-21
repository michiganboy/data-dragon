/**
 * HTML Report Generator
 */

const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
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
    const printCssPath = path.join(__dirname, 'css', 'print.css');
    const jsPath = path.join(__dirname, 'assets', 'report.js');
    
    const css = fs.readFileSync(cssPath, 'utf8');
    const printCss = fs.readFileSync(printCssPath, 'utf8');
    const js = fs.readFileSync(jsPath, 'utf8');
    
    return { css, printCss, js };
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
    const { css, printCss, js } = readAssets();
    
    // Prepare template data with defaults
    const templateData = {
      title: options.title || 'Security Analysis Report',
      dateRange: options.dateRange || `Generated on ${new Date().toLocaleDateString()}`,
      organization: options.organization || 'Your Organization',
      logoPath: options.logoPath || 'images/logo.png',
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
    
    // When generating the HTML file for local viewing, copy the print.css to the assets directory
    const assetsDir = path.join(path.dirname(options.outputPath || ''), 'assets');
    if (!fs.existsSync(assetsDir)) {
      try {
        fs.mkdirSync(assetsDir, { recursive: true });
      } catch (error) {
        throw new Error(`Failed to create assets directory: ${error.message}`);
      }
    }
    
    try {
      fs.writeFileSync(path.join(assetsDir, 'style.css'), css);
      fs.writeFileSync(path.join(assetsDir, 'print.css'), printCss);
    } catch (error) {
      throw new Error(`Failed to write assets files: ${error.message}`);
    }
    
    return html;
  } catch (error) {
    throw new Error(`Failed to generate HTML report: ${error.message}`);
  }
}

/**
 * Generates a security report
 * @param {Object} options - Report generation options
 * @param {Map<string, Object>} options.userActivities - User activity data
 * @param {string} options.outputPath - Path for the generated report
 * @param {Object} options.reportOptions - Additional report options
 * @returns {Promise<Object>} Object containing path to the generated HTML file
 */
async function generateSecurityReport(options) {
  try {
    // Validate required options
    if (!options.userActivities) {
      throw new Error('User activities data is required');
    }
    
    // Convert PDF path to HTML path
    const outputPath = options.outputPath || path.join(process.cwd(), 'output/reports/security-report.pdf');
    const htmlOutputPath = outputPath.replace('.pdf', '.html');
    
    // Ensure output directory exists
    ensureOutputDirectoryExists(htmlOutputPath);
    
    // Transform user data into format suitable for the report
    const reportData = dataTransformer.transformUserData(options.userActivities);
    
    // Generate HTML report
    const html = await generateHtmlReport(reportData, {
      title: options.reportOptions?.title || 'Security Analysis Report',
      dateRange: options.reportOptions?.dateRange,
      organization: options.reportOptions?.organization,
      scanDate: options.reportOptions?.scanDate || new Date(),
      includeAppendix: options.reportOptions?.includeAppendix !== false,
      includeAllWarnings: options.reportOptions?.includeAllWarnings !== false,
      contactInfo: options.reportOptions?.contactInfo,
      outputPath: htmlOutputPath
    });
    
    // Save HTML report
    fs.writeFileSync(htmlOutputPath, html);
    utils.log("info", `HTML report generated at: ${htmlOutputPath}`);
    
    // Return HTML file path
    return {
      htmlPath: htmlOutputPath
    };
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

module.exports = {
  generateSecurityReport,
  getSupportedReportOptions
}; 