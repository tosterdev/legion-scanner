package portscan

type State uint8

const (
	Open State = iota
	Closed
	Timeout
	Unreachable
	Canceled
	Error
)

func (s State) String() string {
	switch s {
	case Open:
		return "open"
	case Closed:
		return "closed"
	case Timeout:
		return "timeout"
	case Unreachable:
		return "unreachable"
	case Canceled:
		return "canceled"
	case Error:
		return "error"
	default:
		return "unknown"
	}
}

