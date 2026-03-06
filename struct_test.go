package sanitizer

import (
	"testing"
)

type Address struct {
	StreetAddress1 string `json:"street_address_1" sanitize:"html"`
	StreetAddress2 string `json:"street_address_2" sanitize:"html"`
	City           string `json:"city" sanitize:"xml"`
	State          string `json:"state"`
	ZipCode        string `json:"zip_code" sanitize:"xss"`
}

type Payload struct {
	FirstName string   `json:"first_name" sanitize:"xss"`
	LastName  string   `json:"last_name" sanitize:"scripts"`
	Age       int      `json:"age"`
	Website   string   `json:"website"  sanitize:"url"`
	Username  string   `json:"username" sanitize:"uri"`
	Address   Address  `json:"address"`
	Active    *bool    `json:"active"`
	LockedBy  *uint8   `json:"locked_by"`
	Tags      []string `json:"tags" sanitize:"xss"`
	Comments  []string `json:"comments" sanitize:"html"`
	Escape    string   `json:"escape" sanitize:"html_escape"`
	Alpha     string   `json:"alpha" sanitize:"alpha"`
	AlphaNum  string   `json:"alpha_num" sanitize:"alphanumeric"`
}

type EmptyStruct struct{}

func TestStruct(t *testing.T) {
	var active = true
	var lockedBy uint8 = 1

	// Payload Example
	payload := &Payload{
		FirstName: `First <script>$("#something").hide()</script>Name 123`,
		LastName:  `Last <embed width="50" class="something"></embed>Name`,
		Age:       30,
		Website:   "https://domain.com",
		Username:  "/This/Works/?that=123&this#page10%",
		Address: Address{
			StreetAddress1: `<!DOCTYPE html><html lang="en"><head><title>Street Address 1</title><link rel="stylesheet" href="style.css"></head><body><script src="index.js"></script></body></html>`,
			StreetAddress2: `<!DOCTYPE html><html lang="en"><head><title>Street Address 2</title><link rel="stylesheet" href="style.css"></head><body><script src="index.js"></script></body></html>`,
			City:           `<CustomTags>City</CustomTags>`,
			State:          ``,
			ZipCode:        `SW1W 0NY<script>$("#something").hide()</script>`,
		},
		Active:   &active,
		LockedBy: &lockedBy,
		Tags: []string{
			`first<script>alert(1)</script>`,
			`second<a href="javascript:alert(1)">link</a>`,
		},
		Comments: []string{
			`hello <b>world</b>`,
			`test <embed src="bad"></embed>`,
		},
		Escape:   `<h1>Escape me!</h1>`,
		Alpha:    "Just letters 123",
		AlphaNum: "Letters and 123 !@#",
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
		{
			name: "Testing non-pointer struct",
			args: args{
				tagName: "sanitize",
				any:     *payload,
			},
			wantErr: true,
		},
		{
			name: "Testing empty struct",
			args: args{
				tagName: "sanitize",
				any:     &EmptyStruct{},
			},
			wantErr: true,
		},
		{
			name: "Testing invalid URL property",
			args: args{
				tagName: "sanitize",
				any: &Payload{
					Website: "http://\x00invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "Testing nested slice invalid URL property",
			args: args{
				tagName: "sanitize",
				any: &struct {
					Urls []string `sanitize:"url"`
				}{
					Urls: []string{"http://\x00invalid"},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Testing struct" {
				// Initialize verbose mode for coverage
				ret := StructSanitizer{verbose: true, tagName: tt.args.tagName}
				if err := ret.SanitizeStruct(tt.args.any); (err != nil) != tt.wantErr {
					t.Errorf("Struct() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err := Struct(tt.args.tagName, tt.args.any); (err != nil) != tt.wantErr {
					t.Errorf("Struct() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			if tt.wantErr {
				return
			}

			// Check for the First name
			if payload.FirstName != "First Name 123" {
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
			if payload.Address.ZipCode != "SW1W 0NY" {
				t.Errorf("ZipCode sanitize error = %v", payload.Address.ZipCode)
			}

			// Check for Tags (Slice xss sanitize)
			if len(payload.Tags) != 2 || payload.Tags[0] != "first" || payload.Tags[1] != "secondlink" {
				t.Errorf("Tags sanitize error = %v", payload.Tags)
			}

			// Check for Comments (Slice html sanitize)
			if len(payload.Comments) != 2 || payload.Comments[0] != "hello world" || payload.Comments[1] != "test " {
				t.Errorf("Comments sanitize error = %v", payload.Comments)
			}

			// Check for Escape
			if payload.Escape != "&lt;h1&gt;Escape me!&lt;/h1&gt;" {
				t.Errorf("Escape sanitize error = %v", payload.Escape)
			}

			// Check for Alpha
			if payload.Alpha != "Just letters " {
				t.Errorf("Alpha sanitize error = %v", payload.Alpha)
			}

			// Check for AlphaNumeric
			if payload.AlphaNum != "Letters and 123 " {
				t.Errorf("AlphaNum sanitize error = %v", payload.AlphaNum)
			}

			// fmt.Printf("%+v", payload)
		})
	}
}
