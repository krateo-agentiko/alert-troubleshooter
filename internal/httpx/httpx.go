// Package httpx holds the HTTP error every outbound call of the alert provider reports.
package httpx

import (
	"errors"
	"fmt"
	"net/http"
)

// StatusError is a 4xx or 5xx answer. Its message is the one Python's requests raised, which the
// Alert and Incident statuses carry.
type StatusError struct {
	Code int
	URL  string
}

func (e *StatusError) Error() string {
	kind := "Client"
	if e.Code >= 500 {
		kind = "Server"
	}
	return fmt.Sprintf("%d %s Error: %s for url: %s", e.Code, kind, http.StatusText(e.Code), e.URL)
}

// Check is a StatusError for a 4xx or 5xx response, else nil.
func Check(resp *http.Response) error {
	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		return &StatusError{Code: resp.StatusCode, URL: resp.Request.URL.String()}
	}
	return nil
}

// Code is the status code of a StatusError in err's chain, or 0.
func Code(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}
