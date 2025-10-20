/**
 * Debug script to check configuration and environment
 */

require('dotenv').config();
const config = require('./config/config');
const fs = require('fs');
const path = require('path');

console.log("🔧 DataDragon Configuration Debug");
console.log("=================================");

// Check environment variables
console.log("\n📋 Environment Variables:");
console.log("SF_LOGIN_URL:", process.env.SF_LOGIN_URL ? "✅ Set" : "❌ Missing");
console.log("SF_CLIENT_ID:", process.env.SF_CLIENT_ID ? "✅ Set" : "❌ Missing");
console.log("SF_CLIENT_SECRET:", process.env.SF_CLIENT_SECRET ? "✅ Set" : "❌ Missing");
console.log("SF_CALLBACK_URL:", process.env.SF_CALLBACK_URL ? "✅ Set" : "❌ Missing");
console.log("TARGET_USERS:", process.env.TARGET_USERS ? "✅ Set" : "❌ Missing");
console.log("USERS_CSV:", process.env.USERS_CSV || "target-users.csv");

// Check configuration
console.log("\n⚙️ Configuration:");
try {
  config.validate();
  console.log("✅ Configuration is valid");
} catch (error) {
  console.log("❌ Configuration error:", error.message);
}

// Check output directories
console.log("\n📁 Output Directories:");
const outputDir = config.OUTPUT_DIR;
const eventLogDir = config.EVENT_LOG_DIR;
const reportsDir = path.join(outputDir, 'reports');

console.log("Output dir exists:", fs.existsSync(outputDir) ? "✅" : "❌");
console.log("Event log dir exists:", fs.existsSync(eventLogDir) ? "✅" : "❌");
console.log("Reports dir exists:", fs.existsSync(reportsDir) ? "✅" : "❌");

// Check dependencies
console.log("\n📦 Dependencies:");
const dependencies = [
  'axios',
  'express', 
  'ejs',
  'chalk',
  'boxen',
  'csv-parser',
  'geoip-lite'
];

dependencies.forEach(dep => {
  try {
    require(dep);
    console.log(`${dep}: ✅`);
  } catch (error) {
    console.log(`${dep}: ❌ Missing`);
  }
});

// Check if target users file exists
console.log("\n👥 Target Users:");
const usersCsv = config.USERS_CSV;
if (fs.existsSync(usersCsv)) {
  console.log(`✅ Users CSV file exists: ${usersCsv}`);
  const content = fs.readFileSync(usersCsv, 'utf8');
  const lines = content.split('\n').filter(line => line.trim());
  console.log(`📊 Found ${lines.length - 1} users (excluding header)`);
} else {
  console.log(`❌ Users CSV file not found: ${usersCsv}`);
  if (config.TARGET_USERS) {
    const users = config.TARGET_USERS.split(',');
    console.log(`📊 Using TARGET_USERS env var: ${users.length} users`);
  } else {
    console.log("❌ No target users configured");
  }
}

console.log("\n🔍 Debug complete!");
