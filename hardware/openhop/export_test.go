package openhop

import "time"

// SetReconnectDelays shortens the backoff schedule for tests.
func SetReconnectDelays(delays []time.Duration) func() {
	prev := reconnectDelays
	reconnectDelays = delays
	return func() { reconnectDelays = prev }
}
