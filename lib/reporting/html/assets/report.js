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
  
  // Get chart data from the data attribute
  const chartData = JSON.parse(riskChartElement.getAttribute('data-chart'));
  if (!chartData || !chartData.labels || !chartData.values) return;
  
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
}

/**
 * Creates event type charts
 */
function createEventTypeCharts() {
  const eventChartElement = document.getElementById('event-type-chart');
  if (!eventChartElement) return;
  
  // Get chart data from the data attribute
  const chartData = JSON.parse(eventChartElement.getAttribute('data-chart'));
  if (!chartData || !chartData.labels || !chartData.values) return;
  
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
}

/**
 * Creates user risk score charts for each user section
 */
function createUserRiskScoreCharts() {
  const userChartElements = document.querySelectorAll('.user-risk-chart');
  
  userChartElements.forEach(element => {
    // Get chart data from the data attribute
    const chartData = JSON.parse(element.getAttribute('data-chart'));
    if (!chartData || !chartData.score) return;
    
    // Create gauge chart for user risk score
    new Chart(element, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [chartData.score, 100 - chartData.score],
          backgroundColor: [
            getRiskLevelColor(chartData.level),
            '#e0e0e0'
          ],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        circumference: 180,
        rotation: 270,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            enabled: false
          }
        },
        cutout: '75%'
      }
    });
    
    // Add risk score text in the center
    const scoreText = document.createElement('div');
    scoreText.className = 'chart-center-text';
    scoreText.textContent = chartData.score;
    scoreText.style.color = getRiskLevelColor(chartData.level);
    
    const chartContainer = element.parentElement;
    chartContainer.style.position = 'relative';
    chartContainer.appendChild(scoreText);
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