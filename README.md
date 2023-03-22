# Sanitizer
This is a string sanitizer for different solutions. 

First you want to include the package in your repository like this.
```go
go get github.com/JoshuaJimenezR/sanitizer
```

### Cleaning strings
Let's say you want to sanitize an url, uri, domain, remove scripts tags from string, remove harmful xss tags to provent attacks. Even remove html, xml or escape these characters. You can do all of that with this package and more. 

```go
sanitizer.Alpha("string", true)
sanitizer.AlphaNumeric("string", true)
sanitizer.HTML("string")
sanitizer.XML("string")
sanitizer.Scripts("string")
sanitizer.HtmlEscape("string")
sanitizer.Domain("string", true)
sanitizer.URL("string")
sanitizer.URI("string")
sanitizer.XSS("string")
```

### Cleaning structs
There is also the feature to clean structs string fields by setting a tag to each field in the struct and specify the type of sanitization you want to apply to each field and even combine many rules into one string, if you want to ommit one of the fields just leave it blank. 

```go
type Payload struct {
    FirstName string `json:"first_name" sanitize:"xss, alpha"`
    LastName  string `json:"last_name" sanitize:"alpha, scripts"`
    Age       int    `json:"age"`
    Website   string `json:"website" sanitize:"url"`
    Username  string `json:"username" sanitize:"uri"`
    Domain    string `json:"domain" sanitize:"domain"`
    Address   struct {
        StreetAddress1 string `json:"street_address_1" sanitize:"html"`
        StreetAddress2 string `json:"street_address_2" sanitize:"html_escape"`
        City           string `json:"city" sanitize:"xml"`
        State          string `json:"state"`
        ZipCode        string `json:"zip_code" sanitize:"alphanumeric, xss"`
    } `json:"address"`
}
```
As of right now we are only checking for strings . We are not checking for maps, slices or other interfaces.  

Here is how you can sanitize an struct. 

```go
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
```

Now you need to send the struct to the sanitizer along with the tag name 

```go
sanitizer.Struct("sanitizer", payload)
```

The pointer struct will be updated with the sanitized fields.
##