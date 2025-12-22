package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TransferHandler manages file transfer operations via HTTP
type TransferHandler struct {
	BaseDir      string
	AllowedHosts []string
	Scripts      map[string]string
}

// TransferRequest represents an incoming transfer request
type TransferRequest struct {
	SourcePath  string `json:"source_path"`
	DestPath    string `json:"dest_path"`
	RemoteURL   string `json:"remote_url"`
	Script      string `json:"script"`
	ScriptArgs  string `json:"script_args"`
	CallbackURL string `json:"callback_url"`
}

// NewTransferHandler creates a new transfer handler
func NewTransferHandler(baseDir string) *TransferHandler {
	return &TransferHandler{
		BaseDir: baseDir,
		Scripts: make(map[string]string),
	}
}

// =============================================================================
// COMPLEX VULNERABILITY: Cross-file Command Injection
// The tainted data flows across multiple functions in this file
// Data flow: HandleTransfer -> ProcessTransfer -> PrepareScript -> BuildCommand -> ExecuteScript
// =============================================================================

// HandleTransfer is the HTTP handler for transfer requests
func (h *TransferHandler) HandleTransfer(w http.ResponseWriter, r *http.Request) {
	var req TransferRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Process the transfer request
	result, err := h.ProcessTransfer(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// ProcessTransfer processes the transfer request and runs associated scripts
func (h *TransferHandler) ProcessTransfer(req *TransferRequest) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// If a script is specified, execute it
	if req.Script != "" {
		scriptOutput, err := h.PrepareScript(req.Script, req.ScriptArgs, req.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("script execution failed: %w", err)
		}
		result["script_output"] = scriptOutput
	}

	// If callback URL is specified, notify it
	if req.CallbackURL != "" {
		err := h.NotifyCallback(req.CallbackURL, req.SourcePath)
		if err != nil {
			result["callback_error"] = err.Error()
		}
	}

	result["status"] = "processed"
	return result, nil
}

// PrepareScript prepares the script for execution
func (h *TransferHandler) PrepareScript(script, args, filePath string) (string, error) {
	// Validate script exists in allowed scripts
	scriptPath := h.ResolveScriptPath(script)

	// Build the command with arguments
	cmdConfig := h.BuildCommand(scriptPath, args, filePath)

	// Execute the script
	return h.ExecuteScript(cmdConfig)
}

// ResolveScriptPath resolves the script path
func (h *TransferHandler) ResolveScriptPath(script string) string {
	// Check if it's a registered script
	if path, ok := h.Scripts[script]; ok {
		return path
	}
	// Otherwise return as-is - VULNERABLE: allows arbitrary script paths
	return script
}

// CommandConfig holds command execution configuration
type CommandConfig struct {
	Program string
	Args    []string
}

// BuildCommand builds the command configuration
// VULNERABLE: User input flows into command arguments
func (h *TransferHandler) BuildCommand(script, args, filePath string) *CommandConfig {
	cmdArgs := []string{}

	// Parse user-provided arguments
	if args != "" {
		// VULNERABLE: User-controlled args split and used directly
		cmdArgs = append(cmdArgs, strings.Split(args, " ")...)
	}

	// Add file path as argument
	if filePath != "" {
		cmdArgs = append(cmdArgs, filePath)
	}

	return &CommandConfig{
		Program: script,
		Args:    cmdArgs,
	}
}

// ExecuteScript executes the script with the given configuration
// SINK: exec.Command with tainted program and arguments
func (h *TransferHandler) ExecuteScript(config *CommandConfig) (string, error) {
	// VULNERABLE: Program and Args come from user input
	cmd := exec.Command(config.Program, config.Args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("execution error: %v, output: %s", err, string(output))
	}
	return string(output), nil
}

// =============================================================================
// COMPLEX VULNERABILITY: Cross-file SSRF
// Data flows: NotifyCallback -> PrepareCallbackRequest -> BuildCallbackURL -> SendCallback
// =============================================================================

// NotifyCallback notifies a callback URL about the transfer
func (h *TransferHandler) NotifyCallback(callbackURL, filePath string) error {
	// Prepare the callback request
	finalURL := h.PrepareCallbackRequest(callbackURL, filePath)

	// Send the callback
	return h.SendCallback(finalURL)
}

// PrepareCallbackRequest prepares the callback URL with file information
func (h *TransferHandler) PrepareCallbackRequest(baseURL, filePath string) string {
	// Add file information to callback
	return h.BuildCallbackURL(baseURL, filePath)
}

// BuildCallbackURL builds the callback URL with query parameters
func (h *TransferHandler) BuildCallbackURL(baseURL, filePath string) string {
	// Extract just the filename for the callback
	fileName := filepath.Base(filePath)

	// Build URL with file info
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&file=%s", baseURL, fileName)
	}
	return fmt.Sprintf("%s?file=%s", baseURL, fileName)
}

// SendCallback sends the HTTP callback request
// SINK: http.Get with user-controlled URL
func (h *TransferHandler) SendCallback(url string) error {
	// VULNERABLE: URL is user-controlled - SSRF
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("callback failed with status: %d", resp.StatusCode)
	}
	return nil
}

// =============================================================================
// COMPLEX VULNERABILITY: Cross-file Path Traversal
// Data flows: HandleFileOp -> ValidateAndProcess -> ResolvePath -> ReadFile/WriteFile
// =============================================================================

// FileOperation represents a file operation request
type FileOperation struct {
	Operation string `json:"operation"` // read, write, copy
	Path      string `json:"path"`
	DestPath  string `json:"dest_path"`
	Content   string `json:"content"`
}

// HandleFileOp handles file operations
func (h *TransferHandler) HandleFileOp(w http.ResponseWriter, r *http.Request) {
	var op FileOperation

	if err := json.NewDecoder(r.Body).Decode(&op); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	result, err := h.ValidateAndProcess(&op)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// ValidateAndProcess validates and processes the file operation
func (h *TransferHandler) ValidateAndProcess(op *FileOperation) (map[string]interface{}, error) {
	// Resolve the path (VULNERABLE: passes user input through)
	resolvedPath := h.ResolvePath(op.Path)

	switch op.Operation {
	case "read":
		content, err := h.ReadFile(resolvedPath)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"content": content}, nil

	case "write":
		err := h.WriteFile(resolvedPath, op.Content)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"status": "written"}, nil

	case "copy":
		destResolved := h.ResolvePath(op.DestPath)
		err := h.CopyFile(resolvedPath, destResolved)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"status": "copied"}, nil
	}

	return nil, fmt.Errorf("unknown operation: %s", op.Operation)
}

// ResolvePath resolves user-provided path
// VULNERABLE: Does not properly sanitize path traversal
func (h *TransferHandler) ResolvePath(userPath string) string {
	// Join with base directory
	// VULNERABLE: filepath.Join doesn't prevent traversal when userPath contains ../
	return filepath.Join(h.BaseDir, userPath)
}

// ReadFile reads file content
// SINK: os.ReadFile with tainted path
func (h *TransferHandler) ReadFile(path string) (string, error) {
	// VULNERABLE: Path comes from user input
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// WriteFile writes content to file
// SINK: os.WriteFile with tainted path
func (h *TransferHandler) WriteFile(path, content string) error {
	// VULNERABLE: Path comes from user input
	return os.WriteFile(path, []byte(content), 0644)
}

// CopyFile copies a file from source to destination
func (h *TransferHandler) CopyFile(src, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, content, 0644)
}
