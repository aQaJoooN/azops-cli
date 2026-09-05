package domain

import (
	"fmt"
	"strings"
)

// HelpRequest is returned when the user passes -h or --help.
type HelpRequest struct {
	Text string
}

func (e *HelpRequest) Error() string { return e.Text }

// UsageError reports invalid command-line input.
type UsageError struct {
	Message string
	Err     error
}

func (e *UsageError) Error() string { return joinError(e.Message, e.Err) }
func (e *UsageError) Unwrap() error { return e.Err }

// DiscoveryError reports a missing or unreadable input file.
type DiscoveryError struct {
	Path string
	Err  error
}

func (e *DiscoveryError) Error() string {
	return joinError(fmt.Sprintf("discover %q", e.Path), e.Err)
}
func (e *DiscoveryError) Unwrap() error { return e.Err }

// DecodeError reports malformed input data.
type DecodeError struct {
	Path  string
	Field string
	Err   error
}

func (e *DecodeError) Error() string {
	location := e.Path
	if e.Field != "" {
		location += ":" + e.Field
	}
	return joinError("decode "+location, e.Err)
}
func (e *DecodeError) Unwrap() error { return e.Err }

// FieldError identifies one invalid configuration field.
type FieldError struct {
	Field   string
	Message string
}

func (e FieldError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return e.Field + ": " + e.Message
}

// ValidationError aggregates independent input validation failures.
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	messages := make([]string, 0, len(e.Errors))
	for _, fieldErr := range e.Errors {
		messages = append(messages, fieldErr.Error())
	}
	return "validation failed: " + strings.Join(messages, "; ")
}

// ConnectionError reports invalid or failed Azure DevOps connectivity.
type ConnectionError struct {
	Message string
	Err     error
}

func (e *ConnectionError) Error() string { return joinError(e.Message, e.Err) }
func (e *ConnectionError) Unwrap() error { return e.Err }

// APIError reports a sanitized non-success Azure DevOps response.
type APIError struct {
	StatusCode int
	RequestID  string
	Message    string
}

func (e *APIError) Error() string {
	message := fmt.Sprintf("Azure DevOps API returned status %d", e.StatusCode)
	if e.RequestID != "" {
		message += " (request " + e.RequestID + ")"
	}
	if e.Message != "" {
		message += ": " + e.Message
	}
	return message
}

// ModuleError adds module and component context to a failure.
type ModuleError struct {
	Module    ModuleID
	Component ComponentPath
	Operation string
	Err       error
}

func (e *ModuleError) Error() string {
	message := fmt.Sprintf("module %s for %s", e.Module, e.Component)
	if e.Operation != "" {
		message += " failed to " + e.Operation
	}
	return joinError(message, e.Err)
}
func (e *ModuleError) Unwrap() error { return e.Err }

func joinError(message string, err error) string {
	if err == nil {
		return message
	}
	if message == "" {
		return err.Error()
	}
	return message + ": " + err.Error()
}
