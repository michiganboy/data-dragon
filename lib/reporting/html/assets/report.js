/**
 * DataDragon Security Report JavaScript
 * Handles charts and interactive elements
 */

// Initialize charts when the document is ready
document.addEventListener('DOMContentLoaded', () => {
  initializeCharts();
  setupEventHandlers();
});

/**
 * Initializes all charts in the report
 */
function initializeCharts() {
  // Risk distribution donut chart
  createRiskDistributionChart();
  
  // Event type charts
  createEventTypeCharts();
  
  // User risk score charts
  createUserRiskScoreCharts();
}

/**
 * Creates the risk distribution donut chart
 */
function createRiskDistributionChart() {
  const riskChartElement = document.getElementById('risk-distribution-chart');
  if (!riskChartElement) return;
  
  try {
    // Get chart data from the data attribute
    const chartData = JSON.parse(riskChartElement.getAttribute('data-chart'));
    if (!chartData || !chartData.labels || !chartData.values || chartData.values.every(val => val === 0)) {
      console.error('Invalid or empty chart data for risk-distribution-chart');
      riskChartElement.parentElement.innerHTML = '<p>No risk data available for visualization</p>';
      return;
    }
    
    // Define colors for each severity level
    const colors = [
      getComputedStyle(document.documentElement).getPropertyValue('--risk-critical').trim(),
      getComputedStyle(document.documentElement).getPropertyValue('--risk-high').trim(),
      getComputedStyle(document.documentElement).getPropertyValue('--risk-medium').trim(),
      getComputedStyle(document.documentElement).getPropertyValue('--risk-low').trim()
    ];
    
    // Create chart using Chart.js
    new Chart(riskChartElement, {
      type: 'doughnut',
      data: {
        labels: chartData.labels,
        datasets: [{
          data: chartData.values,
          backgroundColor: colors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              usePointStyle: true,
              font: {
                family: 'Roboto',
                size: 12
              }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const label = context.label || '';
                const value = context.formattedValue;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = Math.round((context.raw / total) * 100);
                return `${label}: ${value} (${percentage}%)`;
              }
            }
          }
        },
        cutout: '60%'
      }
    });
  } catch (error) {
    console.error('Error creating risk distribution chart:', error);
    riskChartElement.parentElement.innerHTML = '<p>Error creating chart visualization</p>';
  }
}

/**
 * Creates event type charts
 */
function createEventTypeCharts() {
  const eventChartElement = document.getElementById('event-type-chart');
  if (!eventChartElement) return;
  
  try {
    // Get chart data from the data attribute
    const chartData = JSON.parse(eventChartElement.getAttribute('data-chart'));
    if (!chartData || !chartData.labels || !chartData.values || chartData.labels.length === 0) {
      console.error('Invalid or empty chart data for event-type-chart');
      eventChartElement.parentElement.innerHTML = '<p>No event data available for visualization</p>';
      return;
    }
    
    // Use a different color palette for event types
    const colors = chartData.labels.map((_, i) => {
      const hue = (i * 137) % 360; // Use golden ratio to generate colors
      return `hsl(${hue}, 70%, 60%)`;
    });
    
    // Create horizontal bar chart for event types
    new Chart(eventChartElement, {
      type: 'bar',
      data: {
        labels: chartData.labels,
        datasets: [{
          label: 'Events by Type',
          data: chartData.values,
          backgroundColor: colors,
          borderWidth: 0
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          x: {
            ticks: {
              precision: 0 // Ensure whole numbers only
            },
            grid: {
              display: false
            }
          },
          y: {
            grid: {
              display: false
            }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating event type chart:', error);
    eventChartElement.parentElement.innerHTML = '<p>Error creating chart visualization</p>';
  }
}

/**
 * Creates user risk score charts for each user section
 */
function createUserRiskScoreCharts() {
  // First remove any existing Risk Score text that might be causing duplicates
  document.querySelectorAll('.risk-score-text').forEach(el => el.remove());
  
  const userChartElements = document.querySelectorAll('.user-risk-chart');
  
  userChartElements.forEach(element => {
    try {
      // Get chart data from the data attribute
      const chartData = JSON.parse(element.getAttribute('data-chart'));
      if (!chartData || chartData.score === undefined) {
        console.error('Invalid chart data for user risk chart');
        element.parentElement.innerHTML = '<p>Risk score visualization unavailable</p>';
        return;
      }
      
      // Ensure score is between 0 and 100
      const score = Math.max(0, Math.min(100, chartData.score));
      
      // Clear the element
      element.innerHTML = '';
      
      // Create a clean container with fixed width to prevent overlapping
      const container = document.createElement('div');
      container.style.width = '300px';
      container.style.margin = '0 auto 30px auto';
      container.style.position = 'relative';
      
      // Create canvas for the gauge
      const canvas = document.createElement('canvas');
      canvas.height = 150;
      canvas.style.display = 'block';
      
      // Create the score display
      const scoreDisplay = document.createElement('div');
      scoreDisplay.style.textAlign = 'center';
      scoreDisplay.style.marginTop = '-80px';
      
      // Risk level text
      const riskLevel = document.createElement('div');
      riskLevel.textContent = chartData.level.charAt(0).toUpperCase() + chartData.level.slice(1);
      riskLevel.style.fontSize = '16px';
      riskLevel.style.color = '#666';
      
      // Score value
      const scoreValue = document.createElement('div');
      scoreValue.textContent = score;
      scoreValue.style.fontSize = '60px';
      scoreValue.style.fontWeight = 'bold';
      scoreValue.style.color = getRiskLevelColor(chartData.level);
      scoreValue.style.lineHeight = '1';
      
      // Assemble the components
      scoreDisplay.appendChild(riskLevel);
      scoreDisplay.appendChild(scoreValue);
      container.appendChild(canvas);
      container.appendChild(scoreDisplay);
      
      // Replace the original element
      element.parentNode.replaceChild(container, element);
      
      // Calculate data for the gauge chart
      const remainingScore = 100 - score;
      
      // Get risk colors from CSS variables
      const criticalColor = getComputedStyle(document.documentElement).getPropertyValue('--risk-critical').trim();
      const highColor = getComputedStyle(document.documentElement).getPropertyValue('--risk-high').trim();
      const mediumColor = getComputedStyle(document.documentElement).getPropertyValue('--risk-medium').trim();
      const lowColor = getComputedStyle(document.documentElement).getPropertyValue('--risk-low').trim();
      
      // Determine which segments should be colored based on score
      const segmentSize = 25; // Each segment is 25% of the gauge
      const lowSegment = score >= segmentSize ? segmentSize : Math.max(0, score);
      const mediumSegment = score >= segmentSize * 2 ? segmentSize : Math.max(0, score - segmentSize);
      const highSegment = score >= segmentSize * 3 ? segmentSize : Math.max(0, score - segmentSize * 2);
      const criticalSegment = score >= segmentSize * 4 ? segmentSize : Math.max(0, score - segmentSize * 3);
      
      // Create the half-donut chart with distinct color segments
      new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: ['Low', 'Medium', 'High', 'Critical', 'Remaining'],
          datasets: [{
            data: [lowSegment, mediumSegment, highSegment, criticalSegment, remainingScore],
            backgroundColor: [
              lowSegment > 0 ? lowColor : '#e6e6e6',
              mediumSegment > 0 ? mediumColor : '#e6e6e6',
              highSegment > 0 ? highColor : '#e6e6e6',
              criticalSegment > 0 ? criticalColor : '#e6e6e6',
              '#e6e6e6'
            ],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          circumference: 180,
          rotation: 270,
          cutout: '70%',
          plugins: {
            legend: {
              display: false
            },
            tooltip: {
              enabled: false
            }
          },
          layout: {
            padding: {
              top: 0,
              bottom: 20
            }
          }
        },
        plugins: [{
          id: 'gaugeLabels',
          afterRender: function(chart) {
            const width = chart.width;
            const height = chart.height;
            const ctx = chart.ctx;
            
            ctx.save();
            ctx.font = '12px Arial';
            ctx.fillStyle = '#666';
            ctx.textAlign = 'center';
            
            // Draw 0 and 100 labels at the ends of the arc
            ctx.fillText('0', width * 0.1, height * 0.85);
            ctx.fillText('100', width * 0.9, height * 0.85);
            
            ctx.restore();
          }
        }]
      });
      
    } catch (error) {
      console.error('Error creating user risk chart:', error);
      element.parentElement.innerHTML = '<p>Error creating risk score visualization</p>';
    }
  });
}

/**
 * Sets up event handlers for interactive elements
 */
function setupEventHandlers() {
  // Print button functionality
  const printButton = document.getElementById('print-report');
  if (printButton) {
    printButton.addEventListener('click', () => {
      window.print();
    });
  }

  // Toggle visibility of user details sections
  const userToggles = document.querySelectorAll('.user-toggle');
  userToggles.forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      const target = document.getElementById(e.currentTarget.getAttribute('data-target'));
      if (target) {
        const isVisible = target.style.display !== 'none';
        target.style.display = isVisible ? 'none' : 'block';
        e.currentTarget.textContent = isVisible ? 'Show Details' : 'Hide Details';
      }
    });
  });
  
  // Filter risk events by type
  const filterButtons = document.querySelectorAll('.filter-button');
  filterButtons.forEach(button => {
    button.addEventListener('click', (e) => {
      const filterValue = e.currentTarget.getAttribute('data-filter');
      const container = e.currentTarget.closest('.user-profile').querySelector('.risk-events');
      
      // Remove active class from all filter buttons
      e.currentTarget.parentElement.querySelectorAll('.filter-button').forEach(btn => {
        btn.classList.remove('active');
      });
      
      // Add active class to clicked button
      e.currentTarget.classList.add('active');
      
      // Filter the risk events
      if (filterValue === 'all') {
        container.querySelectorAll('.risk-event-card').forEach(card => {
          card.style.display = 'block';
        });
      } else {
        container.querySelectorAll('.risk-event-card').forEach(card => {
          if (card.getAttribute('data-event-type') === filterValue) {
            card.style.display = 'block';
          } else {
            card.style.display = 'none';
          }
        });
      }
    });
  });
}

/**
 * Gets the appropriate color for a risk level
 * @param {string} riskLevel - Risk level (critical, high, medium, low, none)
 * @returns {string} Color value
 */
function getRiskLevelColor(riskLevel) {
  switch(riskLevel.toLowerCase()) {
    case 'critical':
      return getComputedStyle(document.documentElement).getPropertyValue('--risk-critical').trim();
    case 'high':
      return getComputedStyle(document.documentElement).getPropertyValue('--risk-high').trim();
    case 'medium':
      return getComputedStyle(document.documentElement).getPropertyValue('--risk-medium').trim();
    case 'low':
      return getComputedStyle(document.documentElement).getPropertyValue('--risk-low').trim();
    default:
      return getComputedStyle(document.documentElement).getPropertyValue('--risk-none').trim();
  }
} 