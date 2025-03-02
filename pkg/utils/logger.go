package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Logger is a simple logger for the application
type Logger struct {
	verbose bool
	logger  *log.Logger
}

// NewLogger creates a new logger
func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
		logger:  log.New(os.Stderr, "", log.LstdFlags),
	}
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.logger.Printf("[INFO] %s", msg)
}

// Debug logs a debug message (only in verbose mode)
func (l *Logger) Debug(msg string) {
	if l.verbose {
		l.logger.Printf("[DEBUG] %s", msg)
	}
}

// Error logs an error message
func (l *Logger) Error(msg string, err error) {
	l.logger.Printf("[ERROR] %s: %v", msg, err)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, err error) {
	l.logger.Fatalf("[FATAL] %s: %v", msg, err)
}

// Timestamp gets the current timestamp formatted for logging
func (l *Logger) Timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// LogOperation logs the start and end of an operation, returning the elapsed time
func (l *Logger) LogOperation(name string, fn func() error) (time.Duration, error) {
	l.Info(fmt.Sprintf("Starting %s", name))
	start := time.Now()

	err := fn()

	elapsed := time.Since(start)
	if err != nil {
		l.Error(fmt.Sprintf("Failed %s after %v", name, elapsed), err)
	} else {
		l.Info(fmt.Sprintf("Completed %s in %v", name, elapsed))
	}

	return elapsed, err
}
