package crossfile

import "crypto/md5"

// Wrapper defined in a SEPARATE file from its caller. Were Go to register a hook on this wrapper's
// parameter (as Java/Python do), that hook would have to resolve the call recorded while analyzing
// the caller file via the shared, whole-scan call stack — the leg the bucketing narrowing touches.
func HashIt(data []byte) [16]byte {
	return md5.Sum(data)
}
