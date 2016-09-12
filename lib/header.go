package auditx

// Header contains all the header meta for an auditd event
type Header struct {
	Header        byte
	Count         uint64
	Version       byte
	EventType     uint64
	EventModifier uint64
	Seconds       uint64
	Milliseconds  uint64
}
