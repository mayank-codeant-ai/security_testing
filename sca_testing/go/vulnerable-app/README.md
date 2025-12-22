# Go Vulnerable Application - SCA Testing Kit

This Go application contains intentionally vulnerable dependencies for testing Software Composition Analysis (SCA) tools.

## Vulnerable Packages

1. **github.com/dgrijalva/jwt-go v3.2.0**
   - CVE-2020-26160: JWT signature bypass vulnerability
   - Allows attackers to bypass authentication

2. **github.com/gin-gonic/gin v1.6.3**
   - Multiple security vulnerabilities in older versions
   - Path traversal and header injection issues

3. **github.com/gorilla/websocket v1.4.1**
   - CVE-2020-27813: Integer overflow vulnerability
   - Can lead to buffer overflow

4. **gopkg.in/yaml.v2 v2.2.7**
   - CVE-2019-11253: Billion laughs attack
   - CVE-2022-28948: Stack overflow vulnerability
   - YAML parser denial of service

5. **github.com/nats-io/nats-server/v2 v2.1.0**
   - Directory traversal vulnerabilities
   - Unauthorized file access

6. **github.com/tidwall/gjson v1.6.0**
   - CVE-2020-35380: Stack overflow in JSON parsing
   - CVE-2021-42248: Uncontrolled recursion

7. **github.com/russross/blackfriday v1.5.2**
   - XSS vulnerabilities in markdown rendering
   - Allows script injection

8. **golang.org/x/crypto v0.0.0-20200622213623**
   - Old version with known cryptographic vulnerabilities

9. **golang.org/x/net v0.0.0-20200226121028**
   - Old version with HTTP/2 vulnerabilities

## Healthy Packages

1. **github.com/google/uuid v1.3.0**
   - Recent stable version for UUID generation

2. **github.com/sirupsen/logrus v1.9.0**
   - Popular logging library, recent stable version

3. **github.com/stretchr/testify v1.8.1**
   - Testing toolkit, recent stable version

4. **go.uber.org/zap v1.24.0**
   - High-performance logging library

5. **github.com/spf13/cobra v1.6.1**
   - CLI framework, recent stable version

6. **github.com/spf13/viper v1.15.0**
   - Configuration management, recent stable version

## Usage

This application is for testing purposes only. Do not use in production.

### Building
```bash
go build -o vulnerable-app
```

### Running
```bash
./vulnerable-app
```

## Testing SCA Detection

To test the SCA vulnerability scanner:

```bash
cd /path/to/sca_testing/go/vulnerable-app
# Run your SCA tool here
```

Expected results:
- Should detect 9 vulnerable packages
- Should detect 6 healthy packages
- Total packages: 15 direct dependencies + transitive dependencies
