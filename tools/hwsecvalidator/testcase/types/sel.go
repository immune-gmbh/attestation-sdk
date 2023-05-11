package types

// SEL represents a SEL event
type SEL struct {
	// Timestamp is a timestamp of SEL event
	Timestamp int64 `json:"timestamp"`
	// Message is a message of SEL event
	Message string `json:"message"`
}
