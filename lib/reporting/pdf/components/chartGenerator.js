/**
 * Chart generation for PDF reports
 * Creates chart images that can be embedded in PDFs
 */

const { ChartJSNodeCanvas } = require('chartjs-node-canvas');
const styleConfig = require('../utils/styleConfig');

// Configure chart canvas with anti-aliasing
const chartJSNodeCanvas = new ChartJSNodeCanvas({ 
  width: styleConfig.elements.chart.width, 
  height: styleConfig.elements.chart.height,
  backgroundColour: 'white',
  plugins: {
    modern: ['chartjs-plugin-datalabels']
  }
});

/**
 * Generates a pie chart image buffer
 * @param {Object} data - Chart data with labels and datasets
 * @param {Object} options - Chart configuration options
 * @returns {Promise<Buffer>} PNG image buffer
 */
async function generatePieChart(data, options = {}) {
  // Default options
  const chartOptions = {
    plugins: {
      legend: {
        position: 'right',
        labels: {
          font: {
            size: styleConfig.elements.chart.labelFontSize
          }
        }
      },
      title: {
        display: !!options.title,
        text: options.title || '',
        font: {
          size: styleConfig.elements.chart.titleFontSize
        }
      },
      datalabels: {
        color: '#fff',
        font: {
          weight: 'bold'
        },
        formatter: (value, ctx) => {
          if (value === 0) return '';
          return value;
        }
      }
    }
  };

  // Create pie chart configuration
  const configuration = {
    type: 'pie',
    data,
    options: chartOptions
  };

  // Generate chart image
  return chartJSNodeCanvas.renderToBuffer(configuration);
}

/**
 * Generates a bar chart image buffer
 * @param {Object} data - Chart data with labels and datasets
 * @param {Object} options - Chart configuration options
 * @returns {Promise<Buffer>} PNG image buffer
 */
async function generateBarChart(data, options = {}) {
  // Default options
  const chartOptions = {
    indexAxis: options.horizontal ? 'y' : 'x',
    scales: {
      x: {
        ticks: {
          font: {
            size: 10
          }
        }
      },
      y: {
        beginAtZero: true,
        ticks: {
          font: {
            size: 10
          }
        }
      }
    },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          font: {
            size: styleConfig.elements.chart.labelFontSize
          }
        }
      },
      title: {
        display: !!options.title,
        text: options.title || '',
        font: {
          size: styleConfig.elements.chart.titleFontSize
        }
      }
    }
  };

  // Create bar chart configuration
  const configuration = {
    type: 'bar',
    data,
    options: chartOptions
  };

  // Generate chart image
  return chartJSNodeCanvas.renderToBuffer(configuration);
}

/**
 * Generates a line chart image buffer
 * @param {Object} data - Chart data with labels and datasets
 * @param {Object} options - Chart configuration options
 * @returns {Promise<Buffer>} PNG image buffer
 */
async function generateLineChart(data, options = {}) {
  // Default options
  const chartOptions = {
    scales: {
      x: {
        ticks: {
          font: {
            size: 10
          }
        }
      },
      y: {
        beginAtZero: true,
        ticks: {
          font: {
            size: 10
          }
        }
      }
    },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          font: {
            size: styleConfig.elements.chart.labelFontSize
          }
        }
      },
      title: {
        display: !!options.title,
        text: options.title || '',
        font: {
          size: styleConfig.elements.chart.titleFontSize
        }
      }
    }
  };

  // Create line chart configuration
  const configuration = {
    type: 'line',
    data,
    options: chartOptions
  };

  // Generate chart image
  return chartJSNodeCanvas.renderToBuffer(configuration);
}

/**
 * Generates a doughnut chart image buffer
 * @param {Object} data - Chart data with labels and datasets
 * @param {Object} options - Chart configuration options
 * @returns {Promise<Buffer>} PNG image buffer
 */
async function generateDoughnutChart(data, options = {}) {
  // Default options
  const chartOptions = {
    cutout: options.cutout || '50%',
    plugins: {
      legend: {
        position: 'right',
        labels: {
          font: {
            size: styleConfig.elements.chart.labelFontSize
          }
        }
      },
      title: {
        display: !!options.title,
        text: options.title || '',
        font: {
          size: styleConfig.elements.chart.titleFontSize
        }
      },
      datalabels: {
        color: '#fff',
        font: {
          weight: 'bold'
        },
        formatter: (value, ctx) => {
          if (value === 0) return '';
          return value;
        }
      }
    }
  };

  // Create doughnut chart configuration
  const configuration = {
    type: 'doughnut',
    data,
    options: chartOptions
  };

  // Generate chart image
  return chartJSNodeCanvas.renderToBuffer(configuration);
}

/**
 * Creates chart data for event type distribution
 * @param {Array} eventTypes - Array of event types with counts
 * @returns {Object} Formatted chart data
 */
function createEventTypeChartData(eventTypes) {
  // Get top event types (max 8)
  const topTypes = eventTypes.slice(0, 8);
  
  return {
    labels: topTypes.map(t => t.name),
    datasets: [{
      label: 'Event Count',
      data: topTypes.map(t => t.count),
      backgroundColor: [
        '#003366',
        '#0066cc',
        '#3399ff',
        '#66ccff',
        '#ff6600',
        '#ff9900',
        '#ffcc00',
        '#ffff00'
      ]
    }]
  };
}

/**
 * Creates chart data for risk score distribution
 * @param {Array} users - User data array
 * @returns {Object} Formatted chart data
 */
function createRiskScoreDistributionData(users) {
  // Count users in each risk range
  const ranges = {
    'Very High (75+)': 0,
    'High (50-74)': 0,
    'Medium (25-49)': 0,
    'Low (1-24)': 0,
    'None (0)': 0
  };
  
  users.forEach(user => {
    const score = user.riskScore || 0;
    
    if (score >= 75) ranges['Very High (75+)']++;
    else if (score >= 50) ranges['High (50-74)']++;
    else if (score >= 25) ranges['Medium (25-49)']++;
    else if (score > 0) ranges['Low (1-24)']++;
    else ranges['None (0)']++;
  });
  
  return {
    labels: Object.keys(ranges),
    datasets: [{
      label: 'Users',
      data: Object.values(ranges),
      backgroundColor: [
        '#ff0000',
        '#ff9900',
        '#ffcc00',
        '#3399ff',
        '#00cc66'
      ]
    }]
  };
}

module.exports = {
  generatePieChart,
  generateBarChart,
  generateLineChart,
  generateDoughnutChart,
  createEventTypeChartData,
  createRiskScoreDistributionData
}; 