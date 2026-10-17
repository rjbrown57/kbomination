package main

import "testing"

func TestValidateListen(t *testing.T) {
	for _, tc := range []struct {
		address string
		allow   bool
		valid   bool
	}{
		{"127.0.0.1:8080", false, true},
		{"[::1]:8080", false, true},
		{"0.0.0.0:8080", false, false},
		{"[::]:8080", false, false},
		{"192.0.2.1:8080", false, false},
		{"0.0.0.0:8080", true, true},
		{"[::]:8080", true, true},
		{"localhost:8080", true, false},
		{":8080", true, false},
		{"invalid", true, false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			if err := validateListen(tc.address, tc.allow); (err == nil) != tc.valid {
				t.Fatalf("validateListen(%q, %v) = %v, want valid=%v", tc.address, tc.allow, err, tc.valid)
			}
		})
	}
}
