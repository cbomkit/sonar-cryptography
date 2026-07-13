package crossfile

// Caller in a different file from the wrapper. In a hook-based, cross-file world the MD5 usage inside
// HashIt would surface here through the wrapper call. Go registers no such hook today, so this stays
// a plain cross-file call with no detection expected at this site.
func RunHash() [16]byte {
	return HashIt([]byte("data"))
}
