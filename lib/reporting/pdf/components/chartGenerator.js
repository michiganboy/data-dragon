/**
 * Chart generation for PDF reports
 * Creates chart images that can be embedded in PDFs
 */

// Import PDF library
const PDFDocument = require('pdfkit');

/**
 * Simple chart generator that creates basic charts directly in PDFs
 * This implementation avoids the canvas dependencies that require Python
 */
class SimpleChartGenerator {
  /**
   * Generates a pie chart directly in the PDF
   * @param {PDFDocument} doc - PDFKit document
   * @param {number} x - X position
   * @param {number} y - Y position 
   * @param {Object} data - Chart data with labels and values
   * @param {Object} options - Chart options
   */
  static drawPieChart(doc, x, y, data, options = {}) {
    const radius = options.radius || 100;
    const colors = options.colors || ['#4285F4', '#EA4335', '#FBBC05', '#34A853', '#673AB7', '#FF6D00', '#00ACC1'];
    
    // Calculate total value
    const total = data.values.reduce((sum, value) => sum + value, 0);
    
    if (total === 0) return; // Don't draw if no data
    
    // Draw title if provided
    if (options.title) {
      doc.font('Helvetica-Bold').fontSize(12);
      doc.text(options.title, x - radius, y - radius - 20, { width: radius * 2, align: 'center' });
      doc.font('Helvetica').fontSize(10);
    }
    
    // Draw pie slices
    let startAngle = 0;
    let endAngle = 0;
    
    for (let i = 0; i < data.values.length; i++) {
      const value = data.values[i];
      const slice = value / total;
      endAngle = startAngle + slice * Math.PI * 2;
      
      // Draw slice
      doc.save();
      doc.fillColor(colors[i % colors.length]);
      
      // Draw arc
      doc.moveTo(x, y);
      doc.arc(x, y, radius, startAngle, endAngle, false);
      doc.lineTo(x, y);
      doc.fill();
      
      // Prepare for next slice
      startAngle = endAngle;
      doc.restore();
    }
    
    // Draw legend
    const legendX = x + radius + 20;
    const legendY = y - radius;
    
    for (let i = 0; i < data.labels.length; i++) {
      // Draw color box
      doc.rect(legendX, legendY + i * 20, 10, 10)
         .fill(colors[i % colors.length]);
      
      // Draw label and value
      doc.fillColor('black')
         .text(
           `${data.labels[i]}: ${data.values[i]} (${Math.round(data.values[i] / total * 100)}%)`, 
           legendX + 15, 
           legendY + i * 20
         );
    }
  }

  /**
   * Generates a bar chart directly in the PDF
   * @param {PDFDocument} doc - PDFKit document 
   * @param {number} x - X position
   * @param {number} y - Y position
   * @param {Object} data - Chart data with labels and values
   * @param {Object} options - Chart options
   */
  static drawBarChart(doc, x, y, data, options = {}) {
    const width = options.width || 400;
    const height = options.height || 200;
    const colors = options.colors || ['#4285F4'];
    const barSpacing = options.barSpacing || 10;
    
    // Calculate bar width
    const barWidth = (width - ((data.labels.length - 1) * barSpacing)) / data.labels.length;
    
    // Find maximum value for scaling
    const maxValue = Math.max(...data.values);
    
    // Draw title if provided
    if (options.title) {
      doc.font('Helvetica-Bold').fontSize(12);
      doc.text(options.title, x, y - 20, { width: width, align: 'center' });
      doc.font('Helvetica').fontSize(10);
    }
    
    // Draw bars
    for (let i = 0; i < data.labels.length; i++) {
      const value = data.values[i];
      const barHeight = (value / maxValue) * height;
      const barX = x + (i * (barWidth + barSpacing));
      const barY = y + height - barHeight;
      
      // Draw bar
      doc.rect(barX, barY, barWidth, barHeight)
         .fill(colors[i % colors.length]);
      
      // Draw value above bar
      doc.fillColor('black')
         .text(value.toString(), barX, barY - 15, { width: barWidth, align: 'center' });
      
      // Draw label below bar
      doc.fillColor('black')
         .text(data.labels[i], barX, y + height + 5, { width: barWidth, align: 'center' });
    }
    
    // Draw axes
    doc.strokeColor('black')
       .moveTo(x, y)
       .lineTo(x, y + height)
       .lineTo(x + width, y + height)
       .stroke();
  }
}

module.exports = SimpleChartGenerator; 