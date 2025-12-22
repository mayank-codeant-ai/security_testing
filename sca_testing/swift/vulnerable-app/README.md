# Swift Vulnerable Application - SCA Testing Kit

This Swift application contains intentionally vulnerable dependencies for testing Software Composition Analysis (SCA) tools.

## Vulnerable Packages

1. **Alamofire v4.9.0**
   - CVE-2019-8331: Server-side request forgery vulnerability
   - Allows attackers to make unauthorized requests
   - Older version with multiple security issues

2. **SwiftyJSON v4.0.0**
   - JSON parsing vulnerabilities
   - Potential for denial of service through malformed JSON
   - Memory safety issues in older versions

3. **Kingfisher v5.0.0**
   - Image loading vulnerabilities
   - Cache poisoning issues
   - Potential for arbitrary file access

4. **Realm Swift v5.0.0**
   - Data corruption issues in older versions
   - Thread safety problems
   - Potential for data loss

5. **SnapKit v4.0.0**
   - Older version with constraint handling issues
   - Less critical but included for testing

6. **RxSwift v5.0.0**
   - Memory leak issues in older versions
   - Resource management problems
   - Potential for application crashes

## Healthy Packages

1. **SwiftLint v0.50.0**
   - Recent stable version for code linting
   - No known vulnerabilities

2. **Vapor v4.70.0**
   - Modern server-side Swift framework
   - Recent stable version with security fixes

3. **AsyncHTTPClient v1.15.0**
   - Apple's HTTP client library
   - Recent stable version

4. **Swift Argument Parser v1.2.0**
   - Apple's CLI parsing library
   - Recent stable version

5. **Swift Log v1.5.0**
   - Apple's logging API
   - Recent stable version

6. **Swift Crypto v2.5.0**
   - Apple's cryptography library
   - Recent stable version with modern algorithms

## Project Structure

```
vulnerable-app/
├── Package.swift              # Package manifest with dependencies
├── Sources/
│   └── VulnerableApp/
│       └── VulnerableApp.swift  # Main application code
├── Tests/
│   └── VulnerableAppTests/
│       └── VulnerableAppTests.swift  # Unit tests
└── README.md                  # This file
```

## Usage

This application is for testing purposes only. Do not use in production.

### Building

```bash
swift build
```

### Running Tests

```bash
swift test
```

### Running the Application

```bash
swift run vulnerable-app --run-vulnerable
swift run vulnerable-app --run-healthy
```

## Testing SCA Detection

To test the SCA vulnerability scanner:

```bash
cd /path/to/sca_testing/swift/vulnerable-app
# Run your SCA tool here
```

Expected results:
- Should detect 6 vulnerable packages
- Should detect 6 healthy packages
- Total packages: 12 direct dependencies + transitive dependencies

## Vulnerability Details

### Critical Vulnerabilities

- **Alamofire 4.9.0**: SSRF vulnerability allowing unauthorized requests
- **Realm 5.0.0**: Data corruption and thread safety issues
- **RxSwift 5.0.0**: Memory leaks causing application instability

### Medium Vulnerabilities

- **SwiftyJSON 4.0.0**: JSON parsing vulnerabilities
- **Kingfisher 5.0.0**: Image cache poisoning

### Low Vulnerabilities

- **SnapKit 4.0.0**: Constraint handling issues (mostly stability)

## Notes

- This package is designed specifically for testing SCA vulnerability scanners
- All vulnerable versions are intentionally outdated
- The healthy packages represent current best practices
- Code demonstrates usage of both vulnerable and healthy dependencies
