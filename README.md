<p align="center">
  <img src="images/logo.png" alt="DATADRAGON logo">
</p>

Deep within the vaults of your Salesforce org, **DataDragon** slumbers — until someone dares to touch the treasure. With smoke curling from its nostrils and a keen eye for intruders, DataDragon helps security teams investigate user activity by analyzing event logs for suspicious patterns.

## 🐲 Guardian of the Salesforce Hoard

DataDragon is a powerful security investigation tool designed to analyze suspicious activities within your Salesforce organization. By examining EventLogFiles for specific users, DataDragon can identify potential security threats and help protect your data treasure.

## ✨ Features

- 🔐 **SSO-Compatible Authentication**: Works with Salesforce SSO implementations
- 🧩 **Smart Log Selection**: Only processes logs for dates when monitored users logged in
- 🔍 **Advanced Risk Detection**: Comprehensive risk detection patterns across all event types
- 👤 **User Activity Tracking**: Analyzes login patterns and detects behavioral anomalies
- 🚨 **Severity-Based Alerting**: Critical, High, Medium and Low risk classifications
- 📊 **Comprehensive Reporting**: Detailed CSV reports with context-rich data
- 🔄 **Token Caching**: Minimizes authentication requirements
- 🎨 **Themed Console Output**: Clear, colorful, dragon-themed alerts

## 🛠️ Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/datadragon.git
   cd datadragon
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your Salesforce credentials and settings
   ```

## 📋 Prerequisites

1. **Salesforce Connected App**: Create a Connected App in Salesforce with OAuth settings:

   - Callback URL: `http://localhost:3000/oauth/callback`
   - OAuth Scopes:
     - Access and manage your data (api)
     - Perform requests on your behalf at any time (refresh_token, offline_access)
     - Access custom permissions (custom_permissions)

2. **Event Log File Access**: Ensure your Salesforce organization has Event Monitoring enabled and your user has permissions to access Event Log Files.

3. **Permissions**: Your authenticating user needs:
   - "View Event Log Files" permission
   - "API Enabled" permission
   - Access to User and UserLogin objects

## ⚡ Usage

1. Update your `.env` file with your Salesforce Connected App details and configure user targeting:

```
SF_LOGIN_URL=https://yourorg.my.salesforce.com
SF_CLIENT_ID=YOUR_CONNECTED_APP_CONSUMER_KEY
SF_CLIENT_SECRET=YOUR_CONNECTED_APP_CONSUMER_SECRET
SF_CALLBACK_URL=http://localhost:3000/oauth/callback

# For a small number of users, list them directly in the env file
TARGET_USERS=user1@example.com,user2@example.com

# For many users, create a CSV file and reference it
USERS_CSV=target-users.csv
```

2. For large user lists, create a CSV file (default: `target-users.csv`):

```csv
email
user1@example.com
user2@example.com
user3@example.com
...
```

3. Run DataDragon:

```bash
npm run wake-dragon
```

4. DataDragon will:
   - Open a browser window for SSO authentication with Salesforce
   - After successful authentication, display a success message (you may close the browser window)
   - Load users from the CSV file or environment variable
   - Fetch User and UserLogin data to determine which days to scan
   - Download and analyze relevant EventLogFiles
   - Generate reports in the project directory

## 📊 Output Files

DataDragon produces the following output files:

- **output/tokens.json**: Cached authentication tokens
- **output/summary-report.json**: JSON data that could be used for generating additional reports
- **output/summary-report.csv**: CSV report of all detected risks with detailed context information

The CSV report includes:

- User activity information
- Detailed risk context
- Login patterns
- Risk factors explanations
- Specific event details for each warning

The CSV report is designed for easy import into spreadsheet applications for investigation and analysis.

## 🧠 Enhanced Risk Assessment System

DataDragon uses a sophisticated risk assessment system that prioritizes critical security events while avoiding false positives:

### Risk Scoring Methodology

1. **High-Priority Events**: Certain events automatically trigger critical or high risk levels:

   - **Critical Risk Events** (150 points):
     - Report Exports (direct data exfiltration)
     - Organization Data Exports (complete org data extraction)
     - Bulk API Requests with large record counts (mass data operations)
   - **High Risk Events** (100 points):
     - LoginAs (admin impersonation)
     - Direct Apex Execution (system manipulation)
     - Permission Set Assignment (privilege escalation)
     - API Anomalies (platform-detected issues)

2. **Standard Security Warnings**: Other security events add points based on severity:

   - Critical: 50 points
   - High: 30 points
   - Medium: 15 points
   - Low: 5 points

3. **Login Anomalies**: Unusual login patterns also add to the risk score:
   - Rapid IP changes: 25 points (high severity)
   - Unusual login hours: 15 points (medium severity)
   - Weekend activity for weekday-only users: 5 points (low severity)

### Risk Level Assignment

Risk levels are assigned using both event types and cumulative scores:

1. If ANY critical events are detected → Automatic "critical" risk level
2. If ANY high-risk events are detected → Automatic "high" risk level
3. For other cases, score-based thresholds apply:
   - 100+ points → Critical
   - 75-99 points → High
   - 50-74 points → Medium
   - 21-49 points → Low
   - 0-20 points OR no warnings/anomalies → None

This approach ensures critical security events receive immediate attention while minimizing false positives.

## 🔍 Complete Risk Detection Patterns

DataDragon monitors for the following types of suspicious activity:

| Event Type                  | What's Detected                          | Risk Level | Rationale                               |
| --------------------------- | ---------------------------------------- | ---------- | --------------------------------------- |
| ReportExport                | Report Export                            | Critical   | Every export is a potential data exfiltration risk |
| DocumentAttachmentDownloads | Document Download                        | Critical   | Every download is a potential data exfiltration risk |
| ContentDocumentLink         | Excessive Internal Sharing (>20/hour)    | Medium     | May indicate staging for exfiltration   |
| ContentDistribution         | Public Sharing Activity (>5)             | Critical   | Significant data exposure risk          |
| Login                       | Multiple IP Logins (>3)                  | High       | Could indicate compromised credentials  |
| LoginAs                     | Admin Impersonation                      | High       | Admin impersonation warrants review     |
| Sites                       | Internal Access via Guest User           | High       | May indicate misuse of public access    |
| Search                      | Excessive Search Activity (>100/hour)    | High       | Bulk reconnaissance activity            |
| ApexCallout                 | High Volume External Callouts (>30/hour) | High       | May indicate external data exfiltration |
| VisualforceRequest          | Possible Page Scraping (>100/hour)       | High       | Possible scraping or automation         |
| AuraRequest                 | Excessive Component Loading (>200/hour)  | High       | Possible scraping (Lightning)           |
| LightningPageView           | Unusual Page View Volume (>200/hour)     | High       | Recon or bulk record viewing            |
| Dashboard                   | Multiple Dashboard Access (>30/hour)     | Medium     | Unusual recon or data collection        |
| AsyncReportRun              | Background Report Execution              | Critical   | Every background report is a potential data staging risk |
| FlowExecution               | Manual Flow Trigger                      | High       | Direct process manipulation             |
| ApexExecution               | Direct Apex Execution                    | Critical   | Possible direct manipulation or abuse   |
| ApexTriggerExecution        | Apex Trigger Spike (>150)                | Medium     | Unusual mass-trigger events             |
| ApiAnomalyEventStore        | API Anomaly Detected                     | Critical   | Platform detected anomaly               |
| BulkApiRequest              | Bulk API Usage (>10)                     | Medium     | Mass data operations through API        |
| PermissionSetAssignment     | Permission Changes                       | High       | Possible privilege escalation           |
| LightningError              | Unusual Error Rate (>30)                 | Medium     | May indicate attempted exploitation     |
| LogoutEvent                 | Unusual Logout Pattern (>15)             | Low        | May indicate session harvesting         |
| DataExport                  | Organization Data Export                 | Critical   | Every org data export is a critical security event |

Special detection is applied for:

- All report exports (immediate critical risk)
- All document downloads (immediate critical risk)
- All background report executions (immediate critical risk)
- All organization data exports (immediate critical risk)
- Sensitive file type downloads (pdf, xlsx, docx, csv)
- Password-less public shares
- Suspicious rapid IP location changes
- Admin page access
- Critical flow or Apex execution
- Bulk operations with large record counts

## 🛡️ Advanced Configuration

### Custom Risk Thresholds

You can create a `risk-config.json` file to override default risk thresholds:

```json
{
  "ReportExport": {
    "threshold": 1,
    "severity": "critical"
  },
  "DocumentAttachmentDownloads": {
    "threshold": 5,
    "severity": "high"
  }
}
```

### Command Line Options

DataDragon supports several command line options:

```
--debug           Enable debug logging
--days=7          Only scan logs from the last 7 days
--config=path     Specify a custom risk config file
--output=path     Custom location for output files
```

## 🔍 Security Investigation Best Practices

1. **Protect Your Credentials**: Keep your `.env` file secure and never commit it to version control
2. **Focus on Critical Findings**: Prioritize critical and high severity issues
3. **Investigate Context**: Use the detailed context in the CSV report to understand each security event
4. **Correlate Events**: Look for patterns of activity across multiple event types
5. **Review Login Patterns**: Examine unusual login times or locations that coincide with security events

## 🐉 Project Structure

DataDragon is organized in a modular structure:

```
datadragon/
├── index.js                  # Main entry point
├── config/                   # Configuration files
│   ├── config.js             # Application configuration
│   └── riskConfig.js         # Risk detection configuration
├── lib/                      # Core functionality
│   ├── auth.js               # Authentication methods
│   ├── loginDataManager.js   # Login data manager
│   ├── riskCorrelation.js    # Risk correlation engine
│   ├── riskDetection.js      # Risk detection logic
│   ├── reporting.js          # Report generation
│   ├── userLoader.js         # User loading functionality
│   └── utils.js              # Utility functions
├── models/                   # Data models
│   ├── log.js                # Log processing model
│   └── userActivity.js       # User activity and risk assessment
└── output/                   # Output directories
    ├── tokens.json           # Authentication tokens
    ├── summary-report.json   # JSON report
    └── summary-report.csv    # CSV report
```

## 📜 License

MIT License

## 🙏 Acknowledgements

- Salesforce Event Monitoring documentation
- Node.js community
