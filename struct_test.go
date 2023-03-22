package sanitizer

import (
	"fmt"
	"github.com/JoshuaJimenezR/sanitizer/examples"
	"testing"
)

func TestStruct(t *testing.T) {
	// Payload Example
	payload := &examples.Payload{
		FirstName: `First <script>$("#something").hide()</script>Name 123`,
		LastName:  `Last <embed width="50" class="something"></embed>Name`,
		Age:       30,
		Website:   "https://domain.com",
		Username:  "/This/Works/?that=123&this#page10%",
		Address: examples.Address{
			StreetAddress1: `<!DOCTYPE html><html lang="en"><head><title>Street Address 1</title><link rel="stylesheet" href="style.css"></head><body><script src="index.js"></script></body></html>`,
			StreetAddress2: `<!DOCTYPE html><html lang="en"><head><title>Street Address 2</title><link rel="stylesheet" href="style.css"></head><body><script src="index.js"></script></body></html>`,
			City:           `<CustomTags>City</CustomTags>`,
			State:          ``,
			ZipCode:        `SW1W 0NY<script>$("#something").hide()</script>`,
		},
	}

	type args struct {
		tagName string
		any     interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Testing struct",
			args: args{
				tagName: "sanitize",
				any:     payload,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Struct(tt.args.tagName, tt.args.any); (err != nil) != tt.wantErr {
				t.Errorf("Struct() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check for the First name
			if payload.FirstName != "First scriptsomethinghidescriptName " {
				t.Errorf("First Name sanitize error = %v", payload.FirstName)
			}

			// Check for the First name
			if payload.LastName != "Last Name" {
				t.Errorf("Last Name sanitize error = %v", payload.LastName)
			}

			// Check for the Website
			if payload.Website != "https://domain.com" {
				t.Errorf("Website sanitize error = %v", payload.Website)
			}

			// Check for the Username
			if payload.Username != "/This/Works/?that=123&this#page10%" {
				t.Errorf("Username sanitize error = %v", payload.Username)
			}

			// Check for StreetAddress1
			if payload.Address.StreetAddress1 != "Street Address 1" {
				t.Errorf("StreetAddress1 sanitize error = %v", payload.Address.StreetAddress1)
			}

			// Check for StreetAddress2
			if payload.Address.StreetAddress2 != "Street Address 2" {
				t.Errorf("StreetAddress2 sanitize error = %v", payload.Address.StreetAddress2)
			}

			// Check for City
			if payload.Address.City != "City" {
				t.Errorf("City sanitize error = %v", payload.Address.City)
			}

			// Check for Zipcode
			if payload.Address.ZipCode != "SWW NYscriptsomethinghidescript" {
				t.Errorf("ZipCode sanitize error = %v", payload.Address.ZipCode)
			}

			fmt.Printf("%+v", payload)
		})
	}
}
