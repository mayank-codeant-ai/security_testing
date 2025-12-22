package plugins

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
)

// PluginConfig holds configuration for a plugin
type PluginConfig struct {
	Name       string            `json:"name"`
	Enabled    bool              `json:"enabled"`
	ScriptPath string            `json:"script_path"`
	Args       []string          `json:"args"`
	EnvVars    map[string]string `json:"env_vars"`
	Webhook    string            `json:"webhook"`
	DataPath   string            `json:"data_path"`
}

// PluginManager manages plugin lifecycle and execution
type PluginManager struct {
	plugins    map[string]*PluginConfig
	dataDir    string
	db         *sql.DB
	httpClient *http.Client
}

// PluginEvent represents an event that triggers plugins
type PluginEvent struct {
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`
	FilePath   string                 `json:"file_path"`
	Metadata   map[string]interface{} `json:"metadata"`
	WebhookURL string                 `json:"webhook_url"`
	ScriptPath string                 `json:"script_path"`
	ScriptArgs string                 `json:"script_args"`
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(dataDir string) *PluginManager {
	return &PluginManager{
		plugins:    make(map[string]*PluginConfig),
		dataDir:    dataDir,
		httpClient: &http.Client{},
	}
}

// LoadPlugins loads plugins from configuration
func (pm *PluginManager) LoadPlugins(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var plugins []PluginConfig
	if err := json.Unmarshal(data, &plugins); err != nil {
		return err
	}

	for _, p := range plugins {
		pm.plugins[p.Name] = &p
	}
	return nil
}

// =============================================================================
// COMPLEX VULNERABILITY 1: Multi-stage Command Injection
// Data flows through 5+ functions across plugin loading and execution
// Source: HTTP Request -> HandleEvent -> ProcessEvent -> PreparePluginExecution
//         -> BuildPluginCommand -> ValidateAndExecute -> ExecutePlugin (SINK)
// =============================================================================

// HandleEvent handles incoming plugin events via HTTP
func (pm *PluginManager) HandleEvent(w http.ResponseWriter, r *http.Request) {
	var event PluginEvent

	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid event data", http.StatusBadRequest)
		return
	}

	// Process the event through multiple stages
	result, err := pm.ProcessEvent(&event)
	if err != nil {
		http.Error(w, fmt.Sprintf("Event processing failed: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// ProcessEvent processes a plugin event
func (pm *PluginManager) ProcessEvent(event *PluginEvent) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Stage 1: Check if custom script is specified
	if event.ScriptPath != "" {
		output, err := pm.PreparePluginExecution(event)
		if err != nil {
			return nil, err
		}
		result["script_output"] = output
	}

	// Stage 2: Trigger webhook if specified
	if event.WebhookURL != "" {
		err := pm.TriggerEventWebhook(event)
		if err != nil {
			result["webhook_error"] = err.Error()
		} else {
			result["webhook_status"] = "success"
		}
	}

	// Stage 3: Store event if file path specified
	if event.FilePath != "" {
		err := pm.StoreEventData(event)
		if err != nil {
			result["storage_error"] = err.Error()
		}
	}

	result["status"] = "processed"
	return result, nil
}

// PreparePluginExecution prepares the plugin for execution
func (pm *PluginManager) PreparePluginExecution(event *PluginEvent) (string, error) {
	// Build the command configuration
	cmdConfig := pm.BuildPluginCommand(event.ScriptPath, event.ScriptArgs, event.FilePath)

	// Validate and execute
	return pm.ValidateAndExecute(cmdConfig, event.Metadata)
}

// PluginCommandConfig holds the command configuration
type PluginCommandConfig struct {
	Program   string
	Arguments []string
	FilePath  string
	Env       map[string]string
}

// BuildPluginCommand builds the command configuration from event data
func (pm *PluginManager) BuildPluginCommand(scriptPath, args, filePath string) *PluginCommandConfig {
	config := &PluginCommandConfig{
		Program:  scriptPath,
		FilePath: filePath,
		Env:      make(map[string]string),
	}

	// Parse arguments - VULNERABLE: args from user input
	if args != "" {
		config.Arguments = pm.ParseArguments(args)
	}

	// Add file path as last argument
	if filePath != "" {
		config.Arguments = append(config.Arguments, filePath)
	}

	return config
}

// ParseArguments parses command arguments
func (pm *PluginManager) ParseArguments(args string) []string {
	// VULNERABLE: Directly splits user input into command arguments
	return strings.Fields(args)
}

// ValidateAndExecute validates the command and executes it
func (pm *PluginManager) ValidateAndExecute(config *PluginCommandConfig, metadata map[string]interface{}) (string, error) {
	// Add metadata to environment
	if metadata != nil {
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				config.Env[k] = str
			}
		}
	}

	return pm.ExecutePlugin(config)
}

// ExecutePlugin executes the plugin script
// SINK: exec.Command with tainted program and arguments
func (pm *PluginManager) ExecutePlugin(config *PluginCommandConfig) (string, error) {
	// VULNERABLE: Program and Arguments come from user input
	cmd := exec.Command(config.Program, config.Arguments...)

	// Set environment variables
	cmd.Env = os.Environ()
	for k, v := range config.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("plugin execution failed: %v, output: %s", err, string(output))
	}

	return string(output), nil
}

// =============================================================================
// COMPLEX VULNERABILITY 2: Multi-stage SSRF
// Data flows: TriggerEventWebhook -> PrepareWebhookPayload -> BuildNotificationURL
//             -> ConstructFinalURL -> SendEventNotification (SINK)
// =============================================================================

// TriggerEventWebhook triggers a webhook for the event
func (pm *PluginManager) TriggerEventWebhook(event *PluginEvent) error {
	// Prepare the webhook payload
	payload := pm.PrepareWebhookPayload(event)

	// Build the notification URL
	url := pm.BuildNotificationURL(event.WebhookURL, event.Type)

	// Construct final URL with payload
	finalURL := pm.ConstructFinalURL(url, payload)

	// Send the notification
	return pm.SendEventNotification(finalURL)
}

// PrepareWebhookPayload prepares payload data for webhook
func (pm *PluginManager) PrepareWebhookPayload(event *PluginEvent) map[string]string {
	payload := map[string]string{
		"type":   event.Type,
		"source": event.Source,
	}

	if event.FilePath != "" {
		payload["file"] = filepath.Base(event.FilePath)
	}

	return payload
}

// BuildNotificationURL builds the notification URL
func (pm *PluginManager) BuildNotificationURL(baseURL, eventType string) string {
	// Add event type to URL
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&event_type=%s", baseURL, eventType)
	}
	return fmt.Sprintf("%s?event_type=%s", baseURL, eventType)
}

// ConstructFinalURL adds payload parameters to URL
func (pm *PluginManager) ConstructFinalURL(baseURL string, payload map[string]string) string {
	params := ""
	for k, v := range payload {
		if params == "" {
			params = "&"
		}
		params += fmt.Sprintf("%s=%s&", k, v)
	}

	return baseURL + params
}

// SendEventNotification sends the webhook notification
// SINK: http.Get with user-controlled URL
func (pm *PluginManager) SendEventNotification(url string) error {
	// VULNERABLE: URL is constructed from user input - SSRF
	resp, err := pm.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned error status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// =============================================================================
// COMPLEX VULNERABILITY 3: Multi-stage Path Traversal
// Data flows: StoreEventData -> DetermineStoragePath -> CreateStorageFile
//             -> PrepareFilePath -> WriteEventToFile (SINK)
// =============================================================================

// StoreEventData stores event data to file
func (pm *PluginManager) StoreEventData(event *PluginEvent) error {
	// Determine storage path
	storagePath := pm.DetermineStoragePath(event.FilePath, event.Type)

	// Create the storage file
	return pm.CreateStorageFile(storagePath, event)
}

// DetermineStoragePath determines where to store the event data
func (pm *PluginManager) DetermineStoragePath(filePath, eventType string) string {
	// Build path based on file path and event type
	baseName := filepath.Base(filePath)
	eventDir := eventType

	// Combine to create storage path
	return pm.CombineStoragePath(eventDir, baseName)
}

// CombineStoragePath combines directory and filename
func (pm *PluginManager) CombineStoragePath(dir, filename string) string {
	return filepath.Join(pm.dataDir, dir, filename)
}

// CreateStorageFile creates the file and writes event data
func (pm *PluginManager) CreateStorageFile(path string, event *PluginEvent) error {
	// Prepare the final path
	finalPath := pm.PrepareFilePath(path)

	// Write event data
	return pm.WriteEventToFile(finalPath, event)
}

// PrepareFilePath prepares the file path for writing
// VULNERABLE: Does not sanitize path traversal sequences from original FilePath
func (pm *PluginManager) PrepareFilePath(path string) string {
	// Ensure parent directory exists - but path may contain ../
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	return path
}

// WriteEventToFile writes event data to a file
// SINK: os.Create with potentially tainted path
func (pm *PluginManager) WriteEventToFile(path string, event *PluginEvent) error {
	// VULNERABLE: Path is derived from user input (event.FilePath)
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write event as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(event)
}

// =============================================================================
// COMPLEX VULNERABILITY 4: Multi-stage SQL Injection
// Data flows: HandleQuery -> ParseQueryRequest -> BuildDynamicQuery
//             -> PrepareQueryExecution -> ExecuteDatabaseQuery (SINK)
// =============================================================================

// QueryRequest represents a database query request
type QueryRequest struct {
	Table      string   `json:"table"`
	Fields     []string `json:"fields"`
	Conditions string   `json:"conditions"`
	OrderBy    string   `json:"order_by"`
	Limit      int      `json:"limit"`
}

// HandleQuery handles database query requests
func (pm *PluginManager) HandleQuery(w http.ResponseWriter, r *http.Request) {
	var req QueryRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid query request", http.StatusBadRequest)
		return
	}

	// Process the query through multiple stages
	results, err := pm.ParseQueryRequest(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query failed: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(results)
}

// ParseQueryRequest parses and processes the query request
func (pm *PluginManager) ParseQueryRequest(req *QueryRequest) ([]map[string]interface{}, error) {
	// Build the query
	query := pm.BuildDynamicQuery(req)

	// Prepare for execution
	preparedQuery := pm.PrepareQueryExecution(query, req.Limit)

	// Execute the query
	return pm.ExecuteDatabaseQuery(preparedQuery)
}

// BuildDynamicQuery builds the SQL query from request
// VULNERABLE: Direct string concatenation with user input
func (pm *PluginManager) BuildDynamicQuery(req *QueryRequest) string {
	// Build SELECT clause
	fields := "*"
	if len(req.Fields) > 0 {
		fields = strings.Join(req.Fields, ", ")
	}

	// VULNERABLE: Table name and conditions from user input
	query := fmt.Sprintf("SELECT %s FROM %s", fields, req.Table)

	// Add conditions if specified
	if req.Conditions != "" {
		query = pm.AddQueryConditions(query, req.Conditions)
	}

	// Add ORDER BY if specified
	if req.OrderBy != "" {
		query = pm.AddQueryOrdering(query, req.OrderBy)
	}

	return query
}

// AddQueryConditions adds WHERE conditions to query
func (pm *PluginManager) AddQueryConditions(query, conditions string) string {
	// VULNERABLE: Conditions directly concatenated
	return fmt.Sprintf("%s WHERE %s", query, conditions)
}

// AddQueryOrdering adds ORDER BY clause
func (pm *PluginManager) AddQueryOrdering(query, orderBy string) string {
	// VULNERABLE: OrderBy directly concatenated
	return fmt.Sprintf("%s ORDER BY %s", query, orderBy)
}

// PrepareQueryExecution adds LIMIT and finalizes query
func (pm *PluginManager) PrepareQueryExecution(query string, limit int) string {
	if limit > 0 {
		return fmt.Sprintf("%s LIMIT %d", query, limit)
	}
	return query
}

// ExecuteDatabaseQuery executes the SQL query
// SINK: db.Query with tainted SQL string
func (pm *PluginManager) ExecuteDatabaseQuery(query string) ([]map[string]interface{}, error) {
	if pm.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	// VULNERABLE: Query constructed from user input
	rows, err := pm.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// Scan results
	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}

		if err := rows.Scan(pointers...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		results = append(results, row)
	}

	return results, nil
}

// =============================================================================
// COMPLEX VULNERABILITY 5: Multi-stage File Read (Path Traversal variant)
// Data flows: HandleConfig -> LoadConfigFromPath -> ResolveConfigPath
//             -> NormalizePath -> ReadConfigFile (SINK)
// =============================================================================

// HandleConfig handles configuration loading requests
func (pm *PluginManager) HandleConfig(w http.ResponseWriter, r *http.Request) {
	configPath := r.URL.Query().Get("path")
	if configPath == "" {
		http.Error(w, "Config path required", http.StatusBadRequest)
		return
	}

	// Load config through multiple stages
	content, err := pm.LoadConfigFromPath(configPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(content)
}

// LoadConfigFromPath loads configuration from a given path
func (pm *PluginManager) LoadConfigFromPath(userPath string) ([]byte, error) {
	// Resolve the path
	resolvedPath := pm.ResolveConfigPath(userPath)

	// Normalize the path
	normalizedPath := pm.NormalizePath(resolvedPath)

	// Read the config file
	return pm.ReadConfigFile(normalizedPath)
}

// ResolveConfigPath resolves the configuration path
func (pm *PluginManager) ResolveConfigPath(userPath string) string {
	// Combine with data directory
	return filepath.Join(pm.dataDir, "configs", userPath)
}

// NormalizePath normalizes the file path
// VULNERABLE: Does not actually prevent path traversal
func (pm *PluginManager) NormalizePath(path string) string {
	// filepath.Clean doesn't prevent traversal when base is already compromised
	return filepath.Clean(path)
}

// ReadConfigFile reads the configuration file
// SINK: os.ReadFile with tainted path
func (pm *PluginManager) ReadConfigFile(path string) ([]byte, error) {
	// VULNERABLE: Path derived from user input
	return os.ReadFile(path)
}
