/**
 * Table rendering for PDF reports
 * Renders tables with various styling options
 */

const styleConfig = require('../utils/styleConfig');
const { wrapText, truncateText } = require('../utils/pdfHelpers');

/**
 * Renders a table in the PDF document
 * @param {object} doc - PDFKit document
 * @param {object} table - Table configuration object
 * @param {object} options - Rendering options
 * @returns {number} The ending Y position after rendering
 */
function renderTable(doc, table, options = {}) {
  const {
    headers = [],
    rows = [],
    widths = [],
    headerStyles = {},
    cellStyles = {},
    maxRowHeight = 30,
    minRowHeight = 16,
    borders = true,
    zebra = true,
    truncate = {}
  } = table;
  
  // Store starting position
  const startX = doc.x;
  const startY = doc.y;
  
  // Apply default styling
  const fontSize = options.fontSize || styleConfig.elements.table.fontSize;
  doc.fontSize(fontSize);
  
  // Calculate column widths if not provided
  const columnWidths = calculateColumnWidths(
    doc, 
    headers, 
    rows, 
    widths, 
    options.tableWidth || doc.page.width - doc.page.margins.left - doc.page.margins.right
  );
  
  // Calculate header height
  const headerHeight = calculateRowHeight(
    doc, 
    headers, 
    columnWidths, 
    headerStyles.fontSize || fontSize + 1,
    maxRowHeight,
    minRowHeight,
    truncate
  );
  
  // First render the headers
  renderTableRow(
    doc, 
    headers, 
    columnWidths, 
    startX, 
    startY, 
    {
      ...headerStyles,
      isHeader: true,
      fill: headerStyles.fill || styleConfig.elements.table.headerFillColor,
      fontSize: headerStyles.fontSize || fontSize + 1,
      fontBold: headerStyles.fontBold !== false,
      borders,
      truncate
    }
  );
  
  // Update Y position for first data row
  doc.y += headerHeight + (options.cellPadding || styleConfig.elements.table.cellPadding);
  
  // Render each data row
  rows.forEach((row, i) => {
    // Calculate row height
    const rowHeight = calculateRowHeight(
      doc, 
      row, 
      columnWidths, 
      cellStyles.fontSize || fontSize,
      maxRowHeight,
      minRowHeight,
      truncate
    );
    
    // Zebra striping for alternating rows
    const fillColor = zebra && i % 2 === 1 
      ? styleConfig.colors.table.evenRow 
      : styleConfig.colors.table.oddRow;
    
    // Check if we need to add a new page
    if (doc.y + rowHeight > doc.page.height - doc.page.margins.bottom) {
      doc.addPage();
      doc.y = doc.page.margins.top;
      
      // Optionally, re-render header on new page
      if (options.repeatHeader) {
        renderTableRow(
          doc, 
          headers, 
          columnWidths, 
          startX, 
          doc.y, 
          {
            ...headerStyles,
            isHeader: true,
            fill: headerStyles.fill || styleConfig.elements.table.headerFillColor,
            fontSize: headerStyles.fontSize || fontSize + 1,
            fontBold: headerStyles.fontBold !== false,
            borders,
            truncate
          }
        );
        doc.y += headerHeight + (options.cellPadding || styleConfig.elements.table.cellPadding);
      }
    }
    
    // Render the data row
    renderTableRow(
      doc, 
      row, 
      columnWidths, 
      startX, 
      doc.y, 
      {
        ...cellStyles,
        fill: cellStyles.fill || fillColor,
        borders,
        truncate
      }
    );
    
    // Move position for next row
    doc.y += rowHeight + (options.cellPadding || styleConfig.elements.table.cellPadding);
  });
  
  // Return final Y position
  return doc.y;
}

/**
 * Renders a single table row
 * @param {object} doc - PDFKit document
 * @param {array} cells - Cell content array
 * @param {array} widths - Column widths array
 * @param {number} x - Starting X position
 * @param {number} y - Starting Y position
 * @param {object} options - Row rendering options
 * @returns {number} Row height
 */
function renderTableRow(doc, cells, widths, x, y, options = {}) {
  const { 
    fontSize, 
    fontBold, 
    fill, 
    isHeader,
    borders,
    padding = styleConfig.elements.table.cellPadding,
    truncate = {}
  } = options;
  
  // Set font properties
  if (fontSize) doc.fontSize(fontSize);
  if (fontBold) doc.font(`${doc._font.name}-Bold`);
  
  // Calculate row height based on content
  const rowHeight = calculateRowHeight(
    doc, 
    cells, 
    widths, 
    fontSize,
    options.maxRowHeight,
    options.minRowHeight,
    truncate
  );
  
  // Draw the background if specified
  if (fill) {
    doc.save()
       .fillColor(fill)
       .rect(x, y, widths.reduce((a, b) => a + b, 0), rowHeight)
       .fill()
       .restore();
  }
  
  // Draw borders if enabled
  if (borders) {
    doc.save()
       .strokeColor(styleConfig.colors.table.border)
       .lineWidth(styleConfig.elements.table.borderWidth);
    
    // Draw horizontal borders
    doc.moveTo(x, y)
       .lineTo(x + widths.reduce((a, b) => a + b, 0), y)
       .stroke();
    
    doc.moveTo(x, y + rowHeight)
       .lineTo(x + widths.reduce((a, b) => a + b, 0), y + rowHeight)
       .stroke();
    
    // Draw vertical borders
    let currentX = x;
    doc.moveTo(currentX, y)
       .lineTo(currentX, y + rowHeight)
       .stroke();
    
    for (let i = 0; i < widths.length; i++) {
      currentX += widths[i];
      doc.moveTo(currentX, y)
         .lineTo(currentX, y + rowHeight)
         .stroke();
    }
    
    doc.restore();
  }
  
  // Draw each cell's text
  let currentX = x;
  for (let i = 0; i < cells.length; i++) {
    // Skip if no data for this column
    if (i >= widths.length) continue;
    
    const cellWidth = widths[i];
    let cellText = cells[i] != null ? cells[i].toString() : '';
    
    // Handle truncation if specified
    if (truncate[i] || truncate.all) {
      const maxChars = truncate[i] || truncate.all;
      cellText = truncateText(cellText, maxChars);
    }
    
    // Wrap text to fit column
    const textOptions = {
      width: cellWidth - (padding * 2),
      align: options.align || (isHeader ? 'center' : 'left')
    };
    
    // Position for text is centered vertically
    const textX = currentX + padding;
    const textLines = wrapText(cellText, cellWidth - (padding * 2), doc);
    const lineHeight = doc.currentLineHeight(true);
    
    // Calculate vertical centering
    const totalTextHeight = textLines.length * lineHeight;
    let textY = y + padding;
    
    // Center text vertically if it fits
    if (totalTextHeight < rowHeight - (padding * 2)) {
      textY = y + (rowHeight - totalTextHeight) / 2;
    }
    
    // Draw each line of text
    doc.save();
    
    // Set text color based on configuration
    if (options.textColor) {
      doc.fillColor(options.textColor);
    } else {
      doc.fillColor(styleConfig.colors.text.dark);
    }
    
    textLines.forEach((line, lineIndex) => {
      doc.text(
        line,
        textX,
        textY + (lineIndex * lineHeight),
        textOptions
      );
    });
    
    doc.restore();
    
    // Move to next column
    currentX += cellWidth;
  }
  
  // Reset font
  if (fontBold) doc.font(doc._font.name);
  
  return rowHeight;
}

/**
 * Calculates the height needed for a row
 * @param {object} doc - PDFKit document
 * @param {array} cells - Cell content array
 * @param {array} widths - Column widths array
 * @param {number} fontSize - Font size for calculation
 * @param {number} maxRowHeight - Maximum row height
 * @param {number} minRowHeight - Minimum row height
 * @param {object} truncate - Truncation options
 * @returns {number} Calculated row height
 */
function calculateRowHeight(doc, cells, widths, fontSize, maxRowHeight = 30, minRowHeight = 16, truncate = {}) {
  // Set font for correct measurement
  if (fontSize) doc.fontSize(fontSize);
  
  const padding = styleConfig.elements.table.cellPadding * 2;
  let maxHeight = minRowHeight;
  
  // Check each cell's content height
  cells.forEach((cell, i) => {
    // Skip if no data for this column or past available widths
    if (i >= widths.length || cell == null) return;
    
    let cellText = cell.toString();
    
    // Handle truncation if specified
    if (truncate[i] || truncate.all) {
      const maxChars = truncate[i] || truncate.all;
      cellText = truncateText(cellText, maxChars);
    }
    
    // Wrap text and calculate height
    const textLines = wrapText(cellText, widths[i] - padding, doc);
    const lineHeight = doc.currentLineHeight(true);
    const textHeight = textLines.length * lineHeight + padding;
    
    // Update max height if this cell is taller
    if (textHeight > maxHeight) {
      maxHeight = textHeight;
    }
  });
  
  // Enforce maximum row height if specified
  if (maxRowHeight && maxHeight > maxRowHeight) {
    maxHeight = maxRowHeight;
  }
  
  return maxHeight;
}

/**
 * Calculates optimal column widths based on content
 * @param {object} doc - PDFKit document
 * @param {array} headers - Table headers
 * @param {array} rows - Table data rows
 * @param {array} definedWidths - User-defined column widths
 * @param {number} tableWidth - Total table width
 * @returns {array} Calculated column widths
 */
function calculateColumnWidths(doc, headers, rows, definedWidths, tableWidth) {
  const columnCount = Math.max(headers.length, ...rows.map(row => row.length));
  let widths = new Array(columnCount).fill(0);
  
  // If explicit widths provided, use them with adjustments
  if (Array.isArray(definedWidths) && definedWidths.length > 0) {
    // If definedWidths has percentages (values <= 1), convert to actual widths
    const isPercentages = definedWidths.every(w => typeof w === 'number' && w <= 1);
    
    if (isPercentages) {
      widths = definedWidths.map(w => w * tableWidth);
    } else {
      // Copy defined widths
      definedWidths.forEach((width, i) => {
        if (i < widths.length) {
          widths[i] = width;
        }
      });
      
      // If defined widths don't account for all columns, distribute remaining space
      if (definedWidths.length < columnCount) {
        const usedWidth = definedWidths.reduce((sum, width) => sum + width, 0);
        const remainingWidth = tableWidth - usedWidth;
        const remainingColumns = columnCount - definedWidths.length;
        const defaultWidth = remainingWidth / remainingColumns;
        
        for (let i = definedWidths.length; i < columnCount; i++) {
          widths[i] = defaultWidth;
        }
      }
    }
  } else {
    // Auto-calculate based on content
    const minWidth = 40;
    const padding = styleConfig.elements.table.cellPadding * 2;
    
    // Measure content width for each column
    const contentWidths = new Array(columnCount).fill(minWidth);
    
    // Measure headers
    headers.forEach((header, i) => {
      if (header != null) {
        const textWidth = doc.widthOfString(header.toString()) + padding;
        contentWidths[i] = Math.max(contentWidths[i], textWidth);
      }
    });
    
    // Measure rows (sample up to 10 rows for performance)
    const sampleRows = rows.slice(0, 10);
    sampleRows.forEach(row => {
      row.forEach((cell, i) => {
        if (cell != null) {
          const textWidth = doc.widthOfString(cell.toString()) + padding;
          contentWidths[i] = Math.max(contentWidths[i], textWidth);
        }
      });
    });
    
    // Normalize widths to fit table width
    const totalContentWidth = contentWidths.reduce((sum, width) => sum + width, 0);
    
    // Scale to fit if needed
    if (totalContentWidth > tableWidth) {
      const scaleFactor = tableWidth / totalContentWidth;
      widths = contentWidths.map(width => width * scaleFactor);
    } else {
      // Distribute extra space proportionally
      const extraSpace = tableWidth - totalContentWidth;
      widths = contentWidths.map(width => {
        return width + (extraSpace * (width / totalContentWidth));
      });
    }
  }
  
  return widths;
}

module.exports = {
  renderTable
}; 