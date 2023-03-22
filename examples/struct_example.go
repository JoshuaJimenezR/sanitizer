package examples

type Address struct {
	StreetAddress1 string `json:"street_address_1" sanitize:"html"`
	StreetAddress2 string `json:"street_address_2" sanitize:"html_escape"`
	City           string `json:"city" sanitize:"xml"`
	State          string `json:"state"`
	ZipCode        string `json:"zip_code" sanitize:"alphanumeric, xss"`
}

type Payload struct {
	FirstName string  `json:"first_name" sanitize:"xss, alpha"`
	LastName  string  `json:"last_name" sanitize:"alpha, scripts"`
	Age       int     `json:"age"`
	Website   string  `json:"website"  sanitize:"url"`
	Username  string  `json:"username" sanitize:"uri"`
	Address   Address `json:"address"`
}
