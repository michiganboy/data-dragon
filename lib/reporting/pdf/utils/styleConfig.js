/**
 * Styling configuration for PDF reports
 * Defines colors, fonts, margins and other styling elements
 */

const styleConfig = {
  // Page configuration
  page: {
    size: 'A4',
    margins: {
      top: 72,
      bottom: 72,
      left: 72,
      right: 72
    },
    orientation: 'portrait'
  },
  
  // Color palette
  colors: {
    // Primary palette
    primary: '#003366',
    secondary: '#0066cc',
    accent: '#ff6600',
    
    // Text colors
    text: {
      dark: '#333333',
      medium: '#555555',
      light: '#777777'
    },
    
    // Background colors
    background: {
      main: '#ffffff',
      alt: '#f9f9f9',
      highlight: '#f0f7ff'
    },
    
    // Risk level colors
    risk: {
      critical: '#ff0000',
      high: '#ff9900',
      medium: '#ffcc00',
      low: '#3399ff',
      none: '#00cc66'
    },
    
    // Table colors
    table: {
      header: '#e6e6e6',
      oddRow: '#ffffff',
      evenRow: '#f5f5f5',
      border: '#cccccc'
    }
  },
  
  // Typography
  fonts: {
    header: {
      family: 'Helvetica',
      size: {
        title: 24,
        h1: 18,
        h2: 16,
        h3: 14
      },
      style: 'bold'
    },
    body: {
      family: 'Helvetica',
      size: 10,
      lineHeight: 1.4
    },
    monospace: {
      family: 'Courier',
      size: 9
    }
  },
  
  // Spacing values
  spacing: {
    xs: 5,
    sm: 10,
    md: 15,
    lg: 25,
    xl: 40
  },
  
  // Element-specific styling
  elements: {
    // Header styling
    header: {
      height: 60,
      borderBottomWidth: 1,
      borderBottomColor: '#cccccc',
      logoWidth: 150,
      logoHeight: 40
    },
    
    // Footer styling
    footer: {
      height: 40,
      fontSize: 9,
      borderTopWidth: 1,
      borderTopColor: '#cccccc'
    },
    
    // Table styling
    table: {
      cellPadding: 5,
      borderWidth: 0.5,
      headerFillColor: '#e6e6e6',
      fontSize: 9
    },
    
    // Chart styling
    chart: {
      width: 500,
      height: 300,
      titleFontSize: 14,
      labelFontSize: 11
    }
  }
};

module.exports = styleConfig; 