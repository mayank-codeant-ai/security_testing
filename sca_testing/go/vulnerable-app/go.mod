module github.com/test/vulnerable-app

go 1.19

require (
	// Vulnerable packages with known CVEs
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // Has CVE-2020-26160 - JWT signature bypass
	github.com/gin-gonic/gin v1.6.3 // Has multiple vulnerabilities
	github.com/gorilla/websocket v1.4.1 // Has CVE-2020-27813
	gopkg.in/yaml.v2 v2.2.7 // Has CVE-2019-11253, CVE-2022-28948
	github.com/nats-io/nats-server/v2 v2.1.0 // Has directory traversal vulnerabilities
	github.com/tidwall/gjson v1.6.0 // Has CVE-2020-35380, CVE-2021-42248
	github.com/russross/blackfriday v1.5.2 // Has XSS vulnerabilities
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // Old version with vulnerabilities
	golang.org/x/net v0.0.0-20200226121028-0de0cce0169b // Old version with HTTP/2 vulnerabilities

	// Healthy packages (recent stable versions)
	github.com/google/uuid v1.3.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	go.uber.org/zap v1.24.0
	github.com/spf13/cobra v1.6.1
	github.com/spf13/viper v1.15.0
)

require (
	// Transitive dependencies
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.13.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/go-playground/validator/v10 v10.2.0 // indirect
	github.com/golang/protobuf v1.3.3 // indirect
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v0.0.0-20180701023420-4b7aa43c6742 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ugorji/go/codec v1.1.7 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
