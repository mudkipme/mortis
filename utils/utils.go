package utils

// IntPtr returns a pointer to the given int
func IntPtr(i int) *int {
	return &i
}

// StringPtr returns a pointer to the given string
func StringPtr(s string) *string {
	return &s
}

func BoolPtr(b bool) *bool {
	return &b
}
