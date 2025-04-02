/**
 * PDF utility functions
 * Helper functions for common PDF operations
 */

const path = require('path');
const fs = require('fs');

/**
 * Ensures text doesn't overflow the page width
 * @param {string} text - Text to be wrapped
 * @param {number} maxWidth - Maximum width in points
 * @param {object} doc - PDFKit document
 * @returns {string[]} Array of wrapped text lines
 */
function wrapText(text, maxWidth, doc) {
  if (!text) return [''];
  
  // Split text into words
  const words = text.toString().split(' ');
  let lines = [];
  let currentLine = '';

  // Process each word
  words.forEach(word => {
    // Calculate width of line with new word
    const width = doc.widthOfString(currentLine + ' ' + word);
    
    // If adding word exceeds max width, start a new line
    if (width > maxWidth && currentLine !== '') {
      lines.push(currentLine);
      currentLine = word;
    } else {
      // Add word to current line with space if not first word
      if (currentLine === '') {
        currentLine = word;
      } else {
        currentLine += ' ' + word;
      }
    }
  });
  
  // Add the final line
  if (currentLine !== '') {
    lines.push(currentLine);
  }
  
  return lines;
}

/**
 * Truncates text with ellipsis if it exceeds max length
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum string length
 * @returns {string} Truncated text
 */
function truncateText(text, maxLength) {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}

/**
 * Formats a date for the report
 * @param {string|Date} date - Date to format
 * @param {boolean} includeTime - Whether to include time
 * @returns {string} Formatted date
 */
function formatDate(date, includeTime = false) {
  if (!date) return 'N/A';
  
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  
  // Check if valid date
  if (isNaN(dateObj.getTime())) return 'Invalid Date';
  
  const options = {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  };
  
  if (includeTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
  }
  
  return dateObj.toLocaleDateString('en-US', options);
}

/**
 * Loads an image from path for the PDF
 * @param {string} imagePath - Path to the image
 * @param {string} defaultImage - Path to default image if main image not found
 * @returns {Buffer|null} Image buffer or null if not found
 */
function loadImage(imagePath, defaultImage = null) {
  try {
    return fs.readFileSync(imagePath);
  } catch (error) {
    if (defaultImage) {
      try {
        return fs.readFileSync(defaultImage);
      } catch (defaultError) {
        return null;
      }
    }
    return null;
  }
}

/**
 * Formats a number with commas for thousands
 * @param {number} num - Number to format
 * @returns {string} Formatted number
 */
function formatNumber(num) {
  if (num === null || num === undefined) return 'N/A';
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Calculates vertical space needed for text
 * @param {string} text - Text to measure
 * @param {object} doc - PDFKit document
 * @param {number} maxWidth - Maximum width
 * @returns {number} Height in points
 */
function calculateTextHeight(text, doc, maxWidth) {
  if (!text) return 0;
  
  const lines = wrapText(text, maxWidth, doc);
  return lines.length * doc.currentLineHeight(true);
}

/**
 * Draws a horizontal line
 * @param {object} doc - PDFKit document
 * @param {number} y - Y position
 * @param {object} options - Line options
 */
function drawHorizontalLine(doc, y, options = {}) {
  const width = options.width || 0.5;
  const color = options.color || '#cccccc';
  const margin = options.margin || 0;
  
  doc.save()
     .strokeColor(color)
     .lineWidth(width)
     .moveTo(doc.page.margins.left - margin, y)
     .lineTo(doc.page.width - doc.page.margins.right + margin, y)
     .stroke()
     .restore();
}

/**
 * Creates a new page if content won't fit
 * @param {object} doc - PDFKit document
 * @param {number} neededHeight - Height needed for content
 * @param {number} reservedBottom - Space to reserve at bottom
 * @returns {boolean} Whether a new page was added
 */
function ensureSpace(doc, neededHeight, reservedBottom = 50) {
  const availableSpace = doc.page.height - doc.page.margins.bottom - reservedBottom - doc.y;
  
  if (neededHeight > availableSpace) {
    doc.addPage();
    return true;
  }
  
  return false;
}

module.exports = {
  wrapText,
  truncateText,
  formatDate,
  loadImage,
  formatNumber,
  calculateTextHeight,
  drawHorizontalLine,
  ensureSpace
}; 