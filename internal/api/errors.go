package api

import (
	"encoding/json"
	"net/http"
)

// APIError implementiert RFC 7807 (Problem Details for HTTP APIs)
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

const (
	ErrUnauthorized   = "ERR_UNAUTHORIZED"
	ErrInvalidPayload = "ERR_INVALID_PAYLOAD"
	ErrDBWriteFailed  = "ERR_DB_WRITE_FAILED"
)

func SendError(w http.ResponseWriter, status int, code, message, details string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIError{
		Code:    code,
		Message: message,
		Details: details,
	})
}
