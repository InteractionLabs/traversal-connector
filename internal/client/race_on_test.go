//go:build race

package client

// raceEnabled reports that the race detector is compiled in, which inflates
// allocation accounting enough that a test measuring allocation measures the
// detector instead.
const raceEnabled = true
