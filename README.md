# Enhanced Hardcode Security Scanner v2.1

A comprehensive browser-based security scanner that detects hardcoded secrets, API keys, private keys, and other sensitive data in web applications.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Supported Patterns](#supported-patterns)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Export Options](#export-options)
- [Monitoring](#monitoring)
- [Contributing](#contributing)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- **Comprehensive Detection**: Scans for 40+ types of sensitive data including cryptocurrency private keys, API keys, database connections, and more
- **Smart Validation**: Advanced pattern validation with false positive filtering
- **Multiple Scan Modes**: Quick, standard, and deep scanning options
- **Real-time Monitoring**: Continuous monitoring for new secrets
- **Export Capabilities**: Generate reports in JSON, CSV, and HTML formats
- **Framework Detection**: Identifies React, Vue, Angular applications
- **Zero Dependencies**: Pure JavaScript implementation that runs in any modern browser

## Installation

### Method 1: Direct Script Injection

Copy and paste the entire `bot.js` file into your browser console:

```javascript
// Paste the entire bot.js content here
```

### Method 2: Bookmarklet

Create a bookmark with this JavaScript code:

```javascript
javascript:(function(){var script=document.createElement('script');script.src='path/to/bot.js';document.head.appendChild(script);})();
```

### Method 3: Browser Extension Integration

Integrate the scanner into your existing security testing workflow or browser extension.

## Quick Start

After loading the script, the scanner is automatically available as `window.scanner`:

```javascript
// Quick scan (fastest)
scanner.quickScan();

// Standard comprehensive scan
scanner.standardScan();

// Deep analysis with all features
scanner.deepFullScan();
```

## Usage

### Basic Scanning

```javascript
// Run different types of scans
scanner.quickScan();        // DOM + Storage only
scanner.standardScan();     // Most comprehensive
scanner.deepFullScan();     // Includes dynamic content analysis

// Scan specific elements
scanner.scanElement('#login-form');
scanner.scanElement('.api-config');

// Custom scan with options
scanner.scan({
    includeScripts: true,
    includeStorage: true,
    includeCookies: true,
    includeDOM: true,
    includeWindowObject: true,
    includeFetch: true,
    deepScan: false,
    verbose: true
});
```

### Export Results

```javascript
// Export as JSON
scanner.export('json');

// Export as CSV
scanner.export('csv');

// Export as HTML report
scanner.export('html');
```

### Real-time Monitoring

```javascript
// Start monitoring (every 10 seconds)
scanner.startMonitoring();

// Start monitoring with custom interval (every 30 seconds)
scanner.startMonitoring(30000);

// Stop monitoring
scanner.stopMonitoring();
```

### Pattern Testing

```javascript
// Test specific patterns
scanner.testPattern('openai_api_key', 'sk-1234567890abcdef');
scanner.testPattern('bitcoin_private_key_wif', '5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS');

// List all available patterns
scanner.listPatterns();
```

## Supported Patterns

### Cryptocurrency
- Bitcoin private keys (WIF and Hex formats)
- Ethereum private keys
- Solana private keys (Base58 and Uint8Array)
- SUI private keys (Bech32 and Ed25519)
- Mnemonic phrases (12, 15, 18, 21, 24 words)
- Cryptocurrency addresses

### API Keys and Tokens
- AWS Access Keys and Secret Keys
- Google Cloud API Keys and Service Account Keys
- GitHub Personal Access Tokens (Classic and Fine-grained)
- OpenAI API Keys (Legacy and Project-based)
- Stripe API Keys (Live, Test, Restricted)
- JWT Tokens
- Generic API keys and secrets

### Database Connections
- MongoDB connection strings
- PostgreSQL connection strings
- MySQL connection strings

### Private Keys and Certificates
- RSA private keys
- ECDSA private keys
- OpenSSH private keys
- Ed25519 private keys

### Generic Patterns
- Password fields
- Generic secrets and tokens
- Environment variables

## API Reference

### Core Methods

#### `scan(options)`
Runs a customizable scan with specified options.

**Parameters:**
- `options` (Object): Configuration object with scanning preferences

**Options:**
```javascript
{
    includeScripts: boolean,    // Scan external JavaScript files
    includeStorage: boolean,    // Scan localStorage/sessionStorage
    includeCookies: boolean,    // Scan HTTP cookies
    includeDOM: boolean,        // Scan DOM content
    includeWindowObject: boolean, // Scan window object properties
    includeFetch: boolean,      // Monitor network requests
    deepScan: boolean,         // Enable deep analysis
    verbose: boolean           // Detailed output
}
```

#### `quickScan()`
Fast scan focusing on DOM and browser storage.

#### `standardScan()`
Comprehensive scan with most features enabled.

#### `deepFullScan()`
Complete analysis including dynamic content and framework detection.

#### `scanElement(selector)`
Scans a specific DOM element.

**Parameters:**
- `selector` (String|Element): CSS selector or DOM element

#### `export(format)`
Exports scan results in specified format.

**Parameters:**
- `format` (String): 'json', 'csv', or 'html'

#### `startMonitoring(interval)`
Starts real-time monitoring for new secrets.

**Parameters:**
- `interval` (Number): Monitoring interval in milliseconds (default: 10000)

#### `stopMonitoring()`
Stops active monitoring.

#### `testPattern(patternName, testString)`
Tests a specific pattern against a test string.

**Parameters:**
- `patternName` (String): Name of the pattern to test
- `testString` (String): String to test against the pattern

#### `listPatterns()`
Displays all available detection patterns.

### Properties

#### `findings`
Array of detected security findings.

#### `patterns`
Object containing all detection patterns and their configurations.

#### `scannedSources`
Set of already scanned external sources.

#### `falsePositives`
Set of filtered false positive matches.

## Configuration

### Custom Patterns

You can extend the scanner with custom patterns:

```javascript
scanner.patterns.custom_pattern = {
    regex: /your-custom-regex/g,
    severity: '🟡 MEDIUM',
    type: 'Custom Secret Type',
    validate: true,
    validator: (match) => {
        // Custom validation logic
        return true; // or false
    }
};
```

### False Positive Filtering

The scanner includes intelligent false positive filtering for:
- Common placeholder values
- Test data and examples
- Development patterns
- Template variables
- Common development strings

## Export Options

### JSON Format
Complete structured data with metadata, summary statistics, and detailed findings.

### CSV Format
Spreadsheet-compatible format with all finding details.

### HTML Format
Styled report with color-coded severity levels and interactive features.

## Monitoring

The scanner can continuously monitor web applications for new secrets:

```javascript
// Monitor every 10 seconds
scanner.startMonitoring(10000);

// The scanner will automatically detect new findings
// and alert when secrets are discovered
```

## Security Considerations

**Important**: This tool is designed for security testing and should only be used on:
- Applications you own or have explicit permission to test
- Development and staging environments
- Security assessments with proper authorization

**Never use this tool on:**
- Production systems without proper authorization
- Third-party websites without permission
- Applications where you don't have testing rights

## Performance Notes

- **Quick Scan**: ~1-3 seconds, minimal resource usage
- **Standard Scan**: ~5-15 seconds, moderate resource usage  
- **Deep Scan**: ~10-30 seconds, higher resource usage
- **Monitoring**: Minimal continuous overhead

## Browser Compatibility

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

## Troubleshooting

### Common Issues

1. **CORS Errors**: External scripts may not be accessible due to CORS policies
2. **Large Applications**: Deep scans may take longer on complex applications
3. **False Positives**: Use the built-in validation to reduce false positives

### Debug Mode

Enable verbose logging for troubleshooting:

```javascript
scanner.scan({ verbose: true });
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new patterns or improve existing ones
4. Test thoroughly
5. Submit a pull request

### Adding New Patterns

When adding new detection patterns:
1. Include proper regex validation
2. Add false positive filtering
3. Implement custom validators when needed
4. Test with real-world examples
5. Document the pattern purpose and usage

## Changelog

### v2.1
- Enhanced cryptocurrency detection
- Improved false positive filtering
- Added framework detection
- Better export options
- Real-time monitoring capabilities

### v2.0
- Complete rewrite with enhanced patterns
- Added validation layers
- Improved performance
- Better user interface

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is provided for educational and security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any applications. The authors are not responsible for any misuse of this tool.

---

**Made with ❤️ for the security community**