package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	out io.Writer
	mu  sync.Mutex
}

func New(out io.Writer) *Logger {
	return &Logger{out: out}
}

func (l *Logger) Info(message string, fields ...any) {
	l.write("info", message, fields...)
}

func (l *Logger) Error(message string, fields ...any) {
	l.write("error", message, fields...)
}

func (l *Logger) write(level, message string, fields ...any) {
	event := map[string]any{
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
		"level":   level,
		"message": sanitize(message),
	}
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		event[key] = sanitize(fmt.Sprint(fields[i+1]))
	}
	data, _ := json.Marshal(event)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintln(l.out, string(data))
}

func sanitize(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 2048 {
		return value[:2048] + "…"
	}
	return value
}
