package runtime

// Helper functions for pointer operations

// BoolPtr returns a pointer to the given bool value
func BoolPtr(b bool) *bool {
	return &b
}

// Int64Ptr returns a pointer to the given int64 value
func Int64Ptr(i int64) *int64 {
	return &i
}

// StringPtr returns a pointer to the given string value
func StringPtr(s string) *string {
	return &s
}