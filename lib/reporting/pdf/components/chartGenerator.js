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
   * Generates a donut chart directly in the PDF
   * @param {PDFDocument} doc - PDFKit document
   * @param {number} x - X position
   * @param {number} y - Y position 
   * @param {Object} data - Chart data with labels and values
   * @param {Object} options - Chart options
   */
  static drawDonutChart(doc, x, y, data, options = {}) {
    const outerRadius = options.radius || 100;
    const innerRadius = options.innerRadius || (outerRadius * 0.6);
    const colors = options.colors || ['#4285F4', '#EA4335', '#FBBC05', '#34A853', '#673AB7', '#FF6D00', '#00ACC1'];
    
    // Calculate total value
    const total = data.values.reduce((sum, value) => sum + value, 0);
    
    if (total === 0) return; // Don't draw if no data
    
    // Draw title if provided
    if (options.title) {
      doc.font('Helvetica-Bold').fontSize(12);
      doc.text(options.title, x - outerRadius, y - outerRadius - 20, { width: outerRadius * 2, align: 'center' });
      doc.font('Helvetica').fontSize(10);
    }
    
    // Draw donut slices
    let startAngle = 0;
    let endAngle = 0;
    
    for (let i = 0; i < data.values.length; i++) {
      const value = data.values[i];
      const slice = value / total;
      endAngle = startAngle + slice * Math.PI * 2;
      
      // Draw slice
      doc.save();
      doc.fillColor(colors[i % colors.length]);
      
      // Draw outer arc segment
      doc.moveTo(
        x + innerRadius * Math.cos(startAngle),
        y + innerRadius * Math.sin(startAngle)
      );
      
      // Draw outer arc
      doc.arc(x, y, outerRadius, startAngle, endAngle, false);
      
      // Draw inner arc (reverse direction)
      doc.arc(x, y, innerRadius, endAngle, startAngle, true);
      
      doc.fill();
      
      // If not using a legend, draw percentage in each slice
      if (options.showPercentage && slice > 0.05) {
        // Calculate middle angle of the slice
        const midAngle = startAngle + (endAngle - startAngle) / 2;
        
        // Calculate position for text (about 80% of the way from center to edge)
        const labelRadius = innerRadius + (outerRadius - innerRadius) / 2;
        const labelX = x + labelRadius * Math.cos(midAngle);
        const labelY = y + labelRadius * Math.sin(midAngle);
        
        // Determine text color (use white for darker slices)
        doc.fillColor('white');
        
        // Draw percentage
        doc.font('Helvetica-Bold')
           .fontSize(10)
           .text(
             `${Math.round(slice * 100)}%`,
             labelX - 12,
             labelY - 5,
             { width: 24, align: 'center' }
           );
      }
      
      // Prepare for next slice
      startAngle = endAngle;
      doc.restore();
    }
    
    // Add center text if provided
    if (options.centerText) {
      doc.font('Helvetica-Bold')
         .fontSize(options.centerFontSize || 14)
         .fillColor(options.centerTextColor || 'black')
         .text(
           options.centerText,
           x - innerRadius + 10,
           y - 10,
           { width: innerRadius * 2 - 20, align: 'center' }
         );
    }
    
    // Draw legend if not disabled
    if (options.legend !== false) {
      const legendX = x + outerRadius + 20;
      const legendY = y - outerRadius;
      
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
  
  /**
   * Generates a horizontal bar chart directly in the PDF
   * @param {PDFDocument} doc - PDFKit document 
   * @param {number} x - X position
   * @param {number} y - Y position
   * @param {Object} data - Chart data with labels and values
   * @param {Object} options - Chart options
   */
  static drawHorizontalBarChart(doc, x, y, data, options = {}) {
    const width = options.width || 400;
    const height = options.height || 200;
    const colors = options.colors || ['#4285F4'];
    const barSpacing = options.barSpacing || 10;
    const labelWidth = options.labelWidth || 100;
    
    // Calculate bar height based on number of items
    const barHeight = (height - ((data.labels.length - 1) * barSpacing)) / data.labels.length;
    
    // Find maximum value for scaling
    const maxValue = Math.max(...data.values);
    
    // Draw title if provided
    if (options.title) {
      doc.font('Helvetica-Bold').fontSize(12);
      doc.text(options.title, x, y - 20, { width: width + labelWidth, align: 'center' });
      doc.font('Helvetica').fontSize(10);
    }
    
    // Draw bars
    for (let i = 0; i < data.labels.length; i++) {
      const value = data.values[i];
      const barWidth = (value / maxValue) * width;
      const barX = x + labelWidth;
      const barY = y + (i * (barHeight + barSpacing));
      
      // Draw label on left
      doc.fillColor('black')
         .font('Helvetica')
         .text(data.labels[i], x, barY + barHeight/2 - 5, { width: labelWidth - 5, align: 'right' });
      
      // Draw bar
      const barColor = Array.isArray(colors) ? colors[i % colors.length] : colors;
      doc.rect(barX, barY, barWidth, barHeight)
         .fill(barColor);
      
      // Draw value at end of bar
      doc.fillColor('black')
         .text(value.toString(), barX + barWidth + 5, barY + barHeight/2 - 5);
    }
    
    // Draw axes if requested
    if (options.showAxes) {
      doc.strokeColor('black')
         .moveTo(x + labelWidth, y)
         .lineTo(x + labelWidth, y + height)
         .lineTo(x + labelWidth + width, y + height)
         .stroke();
    }
  }
  
  /**
   * Draws a simplified geographical map chart showing risk locations
   * This is a basic implementation since true geographical rendering would be complex
   * @param {PDFDocument} doc - PDFKit document
   * @param {number} x - X position
   * @param {number} y - Y position
   * @param {Array} locations - Array of location data objects {location, count, riskLevel}
   * @param {Object} options - Chart options
   */
  static drawGeoRiskMap(doc, x, y, locations, options = {}) {
    const width = options.width || 500;
    const height = options.height || 300;
    
    // Draw title if provided
    if (options.title) {
      doc.font('Helvetica-Bold').fontSize(14);
      doc.text(options.title, x, y, { width: width, align: 'center' });
      doc.font('Helvetica').fontSize(10);
      y += 25;
    }
    
    // Draw simplified world map outline
    doc.save();
    doc.strokeColor('#cccccc');
    doc.lineWidth(1);
    
    // Draw simplified continent outlines
    // North America
    drawContinentShape(doc, x + width * 0.15, y + height * 0.25, width * 0.2, height * 0.25);
    
    // South America
    drawContinentShape(doc, x + width * 0.25, y + height * 0.5, width * 0.15, height * 0.25);
    
    // Europe
    drawContinentShape(doc, x + width * 0.45, y + height * 0.2, width * 0.1, height * 0.15);
    
    // Africa
    drawContinentShape(doc, x + width * 0.45, y + height * 0.4, width * 0.15, height * 0.25);
    
    // Asia
    drawContinentShape(doc, x + width * 0.6, y + height * 0.25, width * 0.25, height * 0.25);
    
    // Australia
    drawContinentShape(doc, x + width * 0.75, y + height * 0.6, width * 0.1, height * 0.15);
    
    doc.restore();
    
    // Group locations by region for simplified mapping
    const regions = {
      'North America': { x: x + width * 0.2, y: y + height * 0.3, count: 0, risk: 0 },
      'South America': { x: x + width * 0.3, y: y + height * 0.6, count: 0, risk: 0 },
      'Europe': { x: x + width * 0.5, y: y + height * 0.25, count: 0, risk: 0 },
      'Africa': { x: x + width * 0.5, y: y + height * 0.5, count: 0, risk: 0 },
      'Asia': { x: x + width * 0.7, y: y + height * 0.35, count: 0, risk: 0 },
      'Australia': { x: x + width * 0.8, y: y + height * 0.65, count: 0, risk: 0 },
      'Other': { x: x + width * 0.5, y: y + height * 0.8, count: 0, risk: 0 }
    };
    
    // Map location names to regions (simple mapping)
    const regionMapping = {
      'US': 'North America',
      'USA': 'North America',
      'United States': 'North America',
      'Canada': 'North America',
      'Mexico': 'North America',
      
      'Brazil': 'South America',
      'Argentina': 'South America',
      'Chile': 'South America',
      'Colombia': 'South America',
      'Peru': 'South America',
      
      'UK': 'Europe',
      'United Kingdom': 'Europe',
      'France': 'Europe',
      'Germany': 'Europe',
      'Italy': 'Europe',
      'Spain': 'Europe',
      
      'Nigeria': 'Africa',
      'Egypt': 'Africa',
      'South Africa': 'Africa',
      'Kenya': 'Africa',
      'Morocco': 'Africa',
      
      'China': 'Asia',
      'India': 'Asia',
      'Japan': 'Asia',
      'Russia': 'Asia',
      'Indonesia': 'Asia',
      
      'Australia': 'Australia',
      'New Zealand': 'Australia'
    };
    
    // Map risk levels to colors
    const riskColors = options.riskColors || {
      'critical': '#ff0000',
      'high': '#ff6600',
      'medium': '#ffcc00',
      'low': '#3399ff',
      'none': '#00cc66'
    };
    
    // Process locations
    locations.forEach(loc => {
      const locName = loc.location || 'Unknown';
      let region = 'Other';
      
      // Try to map to a region
      Object.keys(regionMapping).forEach(key => {
        if (locName.includes(key)) {
          region = regionMapping[key];
        }
      });
      
      // Add to region counts
      regions[region].count += loc.count || 1;
      
      // Determine risk level weight
      let riskWeight = 1;
      if (loc.riskLevel === 'critical') riskWeight = 4;
      else if (loc.riskLevel === 'high') riskWeight = 3;
      else if (loc.riskLevel === 'medium') riskWeight = 2;
      
      regions[region].risk += riskWeight;
    });
    
    // Draw circles for each region with activity
    Object.values(regions).forEach(region => {
      if (region.count > 0) {
        // Calculate circle size based on count (min 5, max 20)
        const circleSize = Math.max(5, Math.min(20, 5 + region.count * 2));
        
        // Determine color based on risk (red for highest risk)
        const riskLevel = region.risk / region.count;
        let color;
        
        if (riskLevel >= 3.5) color = riskColors.critical;
        else if (riskLevel >= 2.5) color = riskColors.high;
        else if (riskLevel >= 1.5) color = riskColors.medium;
        else color = riskColors.low;
        
        // Draw circle
        doc.circle(region.x, region.y, circleSize)
           .fillAndStroke(color, 'black');
        
        // Add count if large enough
        if (circleSize >= 10) {
          doc.fillColor('white')
             .font('Helvetica-Bold')
             .fontSize(9)
             .text(region.count.toString(), 
                   region.x - 5, 
                   region.y - 5, 
                   { width: 10, align: 'center' });
        }
      }
    });
    
    // Add legend
    const legendY = y + height + 10;
    let legendX = x + 20;
    
    doc.fontSize(10)
       .font('Helvetica-Bold')
       .fillColor('black')
       .text('Risk Levels:', legendX, legendY);
    
    legendX += 80;
    
    Object.entries(riskColors).forEach(([level, color]) => {
      // Draw color circle
      doc.circle(legendX, legendY + 5, 5)
         .fill(color);
      
      // Draw label
      doc.fillColor('black')
         .font('Helvetica')
         .text(level.charAt(0).toUpperCase() + level.slice(1), 
               legendX + 10, 
               legendY);
               
      legendX += 70;
    });
    
    // Return the height used
    return height + 50;
  }
}

/**
 * Helper to draw a simple continent shape
 */
function drawContinentShape(doc, x, y, width, height) {
  // Draw a simple rounded rectangle to represent a continent
  const radius = Math.min(width, height) * 0.2;
  
  doc.roundedRect(x, y, width, height, radius)
     .fillAndStroke('#eeeeee', '#cccccc');
}

module.exports = SimpleChartGenerator; 