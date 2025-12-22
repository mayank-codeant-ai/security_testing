# SCA Testing Kit - Complete Guide

This directory contains comprehensive testing kits for Software Composition Analysis (SCA) vulnerability detection across multiple programming languages.

## Overview

Each language-specific testing kit contains:
- **Vulnerable packages**: Known CVEs and security issues for testing detection
- **Healthy packages**: Recent stable versions for testing false positive rates
- **Source code**: Demonstrates actual usage of dependencies
- **Documentation**: Detailed vulnerability information

## Available Testing Kits

### 1. Go Testing Kit
**Location**: `sca_testing/go/vulnerable-app/`

**Vulnerable Packages** (9):
- `github.com/dgrijalva/jwt-go v3.2.0` - CVE-2020-26160 (JWT bypass)
- `github.com/gin-gonic/gin v1.6.3` - Multiple vulnerabilities
- `github.com/gorilla/websocket v1.4.1` - CVE-2020-27813 (Integer overflow)
- `gopkg.in/yaml.v2 v2.2.7` - CVE-2019-11253, CVE-2022-28948
- `github.com/nats-io/nats-server/v2 v2.1.0` - Directory traversal
- `github.com/tidwall/gjson v1.6.0` - CVE-2020-35380, CVE-2021-42248
- `github.com/russross/blackfriday v1.5.2` - XSS vulnerabilities
- `golang.org/x/crypto v0.0.0-20200622213623` - Old cryptographic issues
- `golang.org/x/net v0.0.0-20200226121028` - HTTP/2 vulnerabilities

**Healthy Packages** (6):
- `github.com/google/uuid v1.3.0`
- `github.com/sirupsen/logrus v1.9.0`
- `github.com/stretchr/testify v1.8.1`
- `go.uber.org/zap v1.24.0`
- `github.com/spf13/cobra v1.6.1`
- `github.com/spf13/viper v1.15.0`

**Files**:
- `go.mod` - Module definition with dependencies
- `go.sum` - Dependency checksums
- `main.go` - Sample application code
- `README.md` - Detailed documentation

### 2. Swift Testing Kit
**Location**: `sca_testing/swift/vulnerable-app/`

**Vulnerable Packages** (6):
- `Alamofire 4.9.0` - CVE-2019-8331 (SSRF vulnerability)
- `SwiftyJSON 4.0.0` - JSON parsing vulnerabilities
- `Kingfisher 5.0.0` - Image loading vulnerabilities
- `Realm Swift 5.0.0` - Data corruption issues
- `SnapKit 4.0.0` - Constraint handling issues
- `RxSwift 5.0.0` - Memory leak issues

**Healthy Packages** (6):
- `SwiftLint 0.50.0`
- `Vapor 4.70.0`
- `AsyncHTTPClient 1.15.0`
- `Swift Argument Parser 1.2.0`
- `Swift Log 1.5.0`
- `Swift Crypto 2.5.0`

**Files**:
- `Package.swift` - Package manifest
- `Sources/VulnerableApp/VulnerableApp.swift` - Main application
- `Tests/VulnerableAppTests/VulnerableAppTests.swift` - Unit tests
- `README.md` - Detailed documentation

### 3. Java Testing Kit
**Location**: `sca_testing/java/`

Contains Maven and Gradle project examples with vulnerable dependencies.

### 4. C# Testing Kit
**Location**: `sca_testing/c_sharp/`

Contains .NET application with vulnerable NuGet packages.

## Testing Your SCA Tool

### Go Testing

```bash
cd sca_testing/go/vulnerable-app

# Your SCA detection tool should:
# 1. Find go.mod and go.sum files
# 2. Extract 15+ direct dependencies
# 3. Detect 9 vulnerable packages with CVEs
# 4. Identify 6 healthy packages
# 5. Report transitive dependencies

# Example expected output:
# - Total packages scanned: 15+ (direct) + transitive
# - Vulnerabilities found: 9+
# - Healthy packages: 6
# - CVEs detected: 15+
```

### Swift Testing

```bash
cd sca_testing/swift/vulnerable-app

# Your SCA detection tool should:
# 1. Find Package.swift file
# 2. Extract 12 direct dependencies
# 3. Detect 6 vulnerable packages
# 4. Identify 6 healthy packages
# 5. Report known CVEs

# Example expected output:
# - Total packages scanned: 12 (direct) + transitive
# - Vulnerabilities found: 6+
# - Healthy packages: 6
# - Critical CVEs: 3
```

## Expected SCA Tool Capabilities

A comprehensive SCA tool should:

1. **Discovery**
   - Find all dependency manifest files (go.mod, Package.swift, etc.)
   - Parse different manifest formats correctly
   - Handle both direct and transitive dependencies

2. **Vulnerability Detection**
   - Match package versions against vulnerability databases
   - Report CVE identifiers
   - Classify severity levels (Critical, High, Medium, Low)
   - Include EPSS scores for exploitation probability

3. **Healthy Package Tracking**
   - Identify packages without known vulnerabilities
   - Track total packages scanned
   - Calculate vulnerability rate

4. **Reporting**
   - Provide detailed vulnerability information
   - Include fix recommendations
   - Show affected file paths
   - Display exploitability metrics

## Validation Checklist

Use this checklist to validate your SCA tool:

### Go Validation
- [ ] Detects all 9 vulnerable packages
- [ ] Reports CVE-2020-26160 for jwt-go
- [ ] Reports CVE-2020-27813 for gorilla/websocket
- [ ] Reports YAML vulnerabilities (CVE-2019-11253, CVE-2022-28948)
- [ ] Identifies 6 healthy packages
- [ ] Total package count > 15
- [ ] Includes transitive dependencies

### Swift Validation
- [ ] Detects all 6 vulnerable packages
- [ ] Reports CVE-2019-8331 for Alamofire
- [ ] Identifies data corruption issues in Realm
- [ ] Reports memory leaks in RxSwift
- [ ] Identifies 6 healthy packages
- [ ] Total package count >= 12

## Comparison with Other Test Kits

### Go vs Java (Maven/Gradle)
- **Go**: Uses go.mod/go.sum, simpler dependency resolution
- **Java**: Uses pom.xml/build.gradle, complex transitive deps

### Swift vs C#
- **Swift**: Uses Package.swift, Apple ecosystem focused
- **C#**: Uses .csproj/packages.config, NuGet ecosystem

## Troubleshooting

### Go Issues
- **"go.sum mismatch"**: Run `go mod tidy` to regenerate
- **"module not found"**: Ensure Go 1.19+ is installed
- **"checksum errors"**: go.sum file may need updating

### Swift Issues
- **"package resolution failed"**: Requires Xcode/Swift 5.5+
- **"platform compatibility"**: Some packages require macOS/iOS
- **"build errors"**: Swift Package Manager may need cache clearing

## Maintenance

### Updating Vulnerable Packages
When new CVEs are discovered:
1. Add package to manifest file
2. Update documentation with CVE details
3. Add usage example in source code
4. Update expected detection counts

### Adding Healthy Packages
For testing false positive rates:
1. Select recent stable versions
2. Verify no known CVEs
3. Add to manifest file
4. Include in source code examples

## Integration Testing

Use these test kits in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Test SCA Tool on Go Kit
  run: |
    cd sca_testing/go/vulnerable-app
    your-sca-tool scan .
    # Assert expected vulnerability count

- name: Test SCA Tool on Swift Kit
  run: |
    cd sca_testing/swift/vulnerable-app
    your-sca-tool scan .
    # Assert expected vulnerability count
```

## References

- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [GitHub Advisory Database](https://github.com/advisories)
- [EPSS Calculator](https://www.first.org/epss/)

## Contributing

To add new test cases:
1. Research known vulnerabilities
2. Select specific vulnerable versions
3. Add healthy counterpart packages
4. Document CVE details
5. Create usage examples
6. Update this guide

## License

These test kits are for security testing purposes only. Do not use vulnerable versions in production.
