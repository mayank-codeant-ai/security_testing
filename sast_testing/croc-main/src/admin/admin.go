package admin

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/schollz/logger"
)

// AdminConfig holds the configuration for the admin server
type AdminConfig struct {
	Port           string   `json:"port"`
	WebhookURL     string   `json:"webhook_url"`
	PostProcessor  string   `json:"post_processor"`
	AllowedPaths   []string `json:"allowed_paths"`
	DatabasePath   string   `json:"database_path"`
	EncryptionType string   `json:"encryption_type"`
}

// TransferRecord holds information about a file transfer for audit logging
type TransferRecord struct {
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	Sender      string `json:"sender"`
	Recipient   string `json:"recipient"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

// AdminServer is the admin HTTP server
type AdminServer struct {
	config   *AdminConfig
	db       *sql.DB
	basePath string
}

// NewAdminServer creates a new admin server
func NewAdminServer(configPath string) (*AdminServer, error) {
	config, err := loadAdminConfig(configPath)
	if err != nil {
		return nil, err
	}

	server := &AdminServer{
		config:   config,
		basePath: ".",
	}

	// Initialize database if path is set
	if config.DatabasePath != "" {
		db, err := initializeDatabase(config.DatabasePath)
		if err != nil {
			return nil, err
		}
		server.db = db
	}

	return server, nil
}

func loadAdminConfig(configPath string) (*AdminConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config AdminConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func initializeDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create audit table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS transfer_audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_name TEXT,
			file_size INTEGER,
			sender TEXT,
			recipient TEXT,
			timestamp TEXT,
			status TEXT,
			description TEXT
		)
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Start starts the admin HTTP server
func (s *AdminServer) Start() error {
	http.HandleFunc("/files/", s.handleFileRequest)
	http.HandleFunc("/audit", s.handleAuditLog)
	http.HandleFunc("/process", s.handlePostProcess)
	http.HandleFunc("/webhook", s.handleWebhookConfig)
	http.HandleFunc("/search", s.handleSearch)

	log.Infof("Starting admin server on port %s", s.config.Port)
	return http.ListenAndServe(":"+s.config.Port, nil)
}

// =============================================================================
// VULNERABILITY 1: Path Traversal
// Data flow: HTTP request -> extractFilePath -> resolvePath -> readFileContent -> os.Open
// The tainted path flows through multiple functions before reaching the sink
// =============================================================================

func (s *AdminServer) handleFileRequest(w http.ResponseWriter, r *http.Request) {
	// Extract the requested path from URL
	requestedPath := r.URL.Path

	// Remove /files/ prefix
	filePath := strings.TrimPrefix(requestedPath, "/files/")

	// Pass through multiple helper functions (complex data flow)
	resolvedPath := s.extractFilePath(filePath, r)
	content, err := s.readFileContent(resolvedPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(content)
}

// extractFilePath processes the path through additional logic
func (s *AdminServer) extractFilePath(path string, r *http.Request) string {
	// Check for query parameter override
	if queryPath := r.URL.Query().Get("path"); queryPath != "" {
		path = queryPath
	}

	// Additional processing through helper
	return s.resolvePath(path)
}

// resolvePath resolves the path relative to base
// VULNERABLE: Does not properly sanitize path traversal sequences
func (s *AdminServer) resolvePath(userPath string) string {
	// Construct full path - VULNERABLE: allows ../ sequences
	fullPath := filepath.Join(s.basePath, userPath)
	return fullPath
}

// readFileContent reads the file content
// SINK: os.Open with tainted path
func (s *AdminServer) readFileContent(path string) ([]byte, error) {
	// This is the sink - path flows from HTTP request through multiple functions
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

// =============================================================================
// VULNERABILITY 2: SQL Injection
// Data flow: HTTP request -> parseAuditData -> buildAuditQuery -> executeAuditQuery -> db.Query
// Tainted user input flows through query construction to SQL execution
// =============================================================================

func (s *AdminServer) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.createAuditRecord(w, r)
		return
	}

	// Handle search/query
	searchTerm := r.URL.Query().Get("search")
	if searchTerm != "" {
		s.searchAuditRecords(w, searchTerm)
		return
	}

	// Return all records
	s.listAuditRecords(w)
}

func (s *AdminServer) createAuditRecord(w http.ResponseWriter, r *http.Request) {
	var record TransferRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Pass data through multiple functions before SQL execution
	query := s.parseAuditData(&record)
	err := s.executeAuditQuery(query)
	if err != nil {
		http.Error(w, "Failed to create audit record", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// parseAuditData builds the audit data
func (s *AdminServer) parseAuditData(record *TransferRecord) string {
	// Pass through another function for "processing"
	return s.buildAuditQuery(record.FileName, record.Sender, record.Description)
}

// buildAuditQuery constructs the SQL query
// VULNERABLE: String concatenation with user input
func (s *AdminServer) buildAuditQuery(fileName, sender, description string) string {
	// VULNERABLE: Direct string concatenation - SQL injection possible
	query := fmt.Sprintf(
		"INSERT INTO transfer_audit (file_name, sender, description, timestamp) VALUES ('%s', '%s', '%s', datetime('now'))",
		fileName, sender, description,
	)
	return query
}

// executeAuditQuery executes the SQL query
// SINK: db.Exec with tainted query
func (s *AdminServer) executeAuditQuery(query string) error {
	if s.db == nil {
		return fmt.Errorf("database not initialized")
	}

	// This is the sink - query contains unsanitized user input
	_, err := s.db.Exec(query)
	return err
}

func (s *AdminServer) searchAuditRecords(w http.ResponseWriter, searchTerm string) {
	// Another SQL injection vector through search
	query := s.buildSearchQuery(searchTerm)
	rows, err := s.executeSearchQuery(query)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []TransferRecord
	for rows.Next() {
		var r TransferRecord
		if err := rows.Scan(&r.FileName, &r.Sender, &r.Description, &r.Timestamp); err != nil {
			continue
		}
		records = append(records, r)
	}

	json.NewEncoder(w).Encode(records)
}

// buildSearchQuery builds search query
// VULNERABLE: String concatenation
func (s *AdminServer) buildSearchQuery(term string) string {
	// VULNERABLE: Direct concatenation allows SQL injection
	return fmt.Sprintf("SELECT file_name, sender, description, timestamp FROM transfer_audit WHERE file_name LIKE '%%%s%%' OR description LIKE '%%%s%%'", term, term)
}

// executeSearchQuery executes search
// SINK: db.Query with tainted query
func (s *AdminServer) executeSearchQuery(query string) (*sql.Rows, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	return s.db.Query(query)
}

func (s *AdminServer) listAuditRecords(w http.ResponseWriter) {
	if s.db == nil {
		http.Error(w, "Database not initialized", http.StatusInternalServerError)
		return
	}

	rows, err := s.db.Query("SELECT file_name, sender, description, timestamp FROM transfer_audit")
	if err != nil {
		http.Error(w, "Failed to retrieve records", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var records []TransferRecord
	for rows.Next() {
		var r TransferRecord
		if err := rows.Scan(&r.FileName, &r.Sender, &r.Description, &r.Timestamp); err != nil {
			continue
		}
		records = append(records, r)
	}

	json.NewEncoder(w).Encode(records)
}

// =============================================================================
// VULNERABILITY 3: Command Injection
// Data flow: HTTP request -> parseProcessConfig -> buildCommandArgs -> executeProcessor -> exec.Command
// User-controlled input flows through command construction to execution
// =============================================================================

func (s *AdminServer) handlePostProcess(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FilePath   string            `json:"file_path"`
		Processor  string            `json:"processor"`
		Args       string            `json:"args"`
		EnvVars    map[string]string `json:"env_vars"`
		WorkingDir string            `json:"working_dir"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Pass through multiple functions (complex data flow)
	cmdConfig := s.parseProcessConfig(request.Processor, request.Args, request.FilePath)
	output, err := s.executeProcessor(cmdConfig, request.EnvVars, request.WorkingDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("Execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// ProcessConfig holds command configuration
type ProcessConfig struct {
	Command string
	Args    []string
	Input   string
}

// parseProcessConfig parses and prepares the command config
func (s *AdminServer) parseProcessConfig(processor, args, filePath string) *ProcessConfig {
	// Use configured processor or request processor
	cmd := processor
	if cmd == "" {
		cmd = s.config.PostProcessor
	}

	// Build arguments through helper
	cmdArgs := s.buildCommandArgs(args, filePath)

	return &ProcessConfig{
		Command: cmd,
		Args:    cmdArgs,
		Input:   filePath,
	}
}

// buildCommandArgs builds the command arguments
func (s *AdminServer) buildCommandArgs(userArgs, filePath string) []string {
	args := []string{}

	// Add user-provided arguments - VULNERABLE: no sanitization
	if userArgs != "" {
		// Split user args and append
		args = append(args, strings.Fields(userArgs)...)
	}

	// Add the file path
	if filePath != "" {
		args = append(args, filePath)
	}

	return args
}

// executeProcessor executes the command
// SINK: exec.Command with tainted arguments
func (s *AdminServer) executeProcessor(config *ProcessConfig, envVars map[string]string, workingDir string) ([]byte, error) {
	// VULNERABLE: Command and arguments come from user input
	cmd := exec.Command(config.Command, config.Args...)

	// Set environment variables from user input
	if len(envVars) > 0 {
		cmd.Env = os.Environ()
		for k, v := range envVars {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Set working directory from user input
	if workingDir != "" {
		cmd.Dir = workingDir
	}

	return cmd.CombinedOutput()
}

// =============================================================================
// VULNERABILITY 4: SSRF (Server-Side Request Forgery)
// Data flow: HTTP request -> extractWebhookURL -> prepareWebhookRequest -> sendWebhook -> http.Get
// User-controlled URL flows through request preparation to HTTP call
// =============================================================================

func (s *AdminServer) handleWebhookConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.triggerWebhook(w, r)
		return
	}

	// Return current webhook config
	json.NewEncoder(w).Encode(map[string]string{
		"webhook_url": s.config.WebhookURL,
	})
}

func (s *AdminServer) triggerWebhook(w http.ResponseWriter, r *http.Request) {
	var request struct {
		URL     string            `json:"url"`
		Event   string            `json:"event"`
		Payload map[string]string `json:"payload"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Complex data flow through multiple functions
	webhookURL := s.extractWebhookURL(request.URL, request.Event)
	response, err := s.prepareWebhookRequest(webhookURL, request.Payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("Webhook failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(response)
}

// extractWebhookURL determines the webhook URL to use
func (s *AdminServer) extractWebhookURL(requestURL, event string) string {
	// Prefer request URL if provided, otherwise use config
	url := requestURL
	if url == "" {
		url = s.config.WebhookURL
	}

	// Append event to URL
	if event != "" {
		url = s.appendEventToURL(url, event)
	}

	return url
}

// appendEventToURL adds event as query parameter
func (s *AdminServer) appendEventToURL(baseURL, event string) string {
	if strings.Contains(baseURL, "?") {
		return baseURL + "&event=" + event
	}
	return baseURL + "?event=" + event
}

// prepareWebhookRequest prepares and sends the webhook
func (s *AdminServer) prepareWebhookRequest(url string, payload map[string]string) ([]byte, error) {
	// Add payload to URL or prepare request
	finalURL := s.buildWebhookURL(url, payload)
	return s.sendWebhook(finalURL)
}

// buildWebhookURL adds payload to URL
func (s *AdminServer) buildWebhookURL(baseURL string, payload map[string]string) string {
	// Append payload as query params
	params := ""
	for k, v := range payload {
		if params == "" {
			if strings.Contains(baseURL, "?") {
				params = "&"
			} else {
				params = "?"
			}
		} else {
			params += "&"
		}
		params += fmt.Sprintf("%s=%s", k, v)
	}

	return baseURL + params
}

// sendWebhook makes the HTTP request
// SINK: http.Get with user-controlled URL
func (s *AdminServer) sendWebhook(url string) ([]byte, error) {
	// VULNERABLE: URL comes from user input - SSRF possible
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// =============================================================================
// VULNERABILITY 5: Weak Cryptography / Insecure Hash Usage
// Data flow: config -> selectHashAlgorithm -> deriveKey -> WeakHash
// This demonstrates using MD5 or other weak algorithms based on config
// =============================================================================

func (s *AdminServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	algorithm := r.URL.Query().Get("hash_algo")

	// Process search with configurable hash
	result := s.processSearchWithHash(query, algorithm)

	json.NewEncoder(w).Encode(map[string]string{
		"hash": result,
	})
}

// processSearchWithHash processes search term with configurable hash
func (s *AdminServer) processSearchWithHash(term, algorithm string) string {
	// Use algorithm from request or config
	algo := s.selectHashAlgorithm(algorithm)
	return s.computeHash(term, algo)
}

// selectHashAlgorithm selects the hash algorithm
func (s *AdminServer) selectHashAlgorithm(requested string) string {
	if requested != "" {
		return requested
	}
	if s.config.EncryptionType != "" {
		return s.config.EncryptionType
	}
	return "md5" // Default to weak MD5 - VULNERABLE
}

// computeHash computes hash with specified algorithm
// VULNERABLE: Allows use of weak cryptographic algorithms (MD5)
func (s *AdminServer) computeHash(data, algorithm string) string {
	switch algorithm {
	case "md5":
		// VULNERABLE: MD5 is cryptographically weak
		return computeMD5(data)
	case "sha1":
		// VULNERABLE: SHA1 is cryptographically weak
		return computeSHA1(data)
	default:
		return computeMD5(data) // Default to weak MD5
	}
}

// computeMD5 computes MD5 hash - VULNERABLE
func computeMD5(data string) string {
	// Using crypto/md5 - weak for security purposes
	// This is detected by weak-crypto rules
	hash := fmt.Sprintf("%x", []byte(data)) // Simplified for demo
	return hash
}

// computeSHA1 computes SHA1 hash - VULNERABLE
func computeSHA1(data string) string {
	// Using crypto/sha1 - weak for security purposes
	hash := fmt.Sprintf("%x", []byte(data)) // Simplified for demo
	return hash
}
