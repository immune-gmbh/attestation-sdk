package intel

// ErrNoBPM means that no boot policy manifest was found
type ErrNoBPM struct{}

// Error implements error.
func (err ErrNoBPM) Error() string {
	return "no BPM entry found in FIT"
}
