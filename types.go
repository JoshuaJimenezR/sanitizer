package sanitizer

import (
	"errors"
	"fmt"
	"github.com/robertkrimen/otto"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// Regular Expression rules
var (
	alphaRegex                  = regexp.MustCompile("[^a-zA-Z]+")     // alpha characters
	alphaWithSpacesRegex        = regexp.MustCompile("[^a-zA-Z ]+")    // alpha characters with spaces
	alphaNumericRegex           = regexp.MustCompile("[^a-zA-Z0-9]+")  // alphanumeric characters
	alphaNumericWithSpacesRegex = regexp.MustCompile("[^a-zA-Z0-9 ]+") // alphanumeric characters with spaces
	domainRegex                 = regexp.MustCompile(`[^a-zA-Z0-9-.]`) // domain accepted characters
	htmlRegex                   = regexp.MustCompile(`<[^>]*>`)        // html/xml tags or any alligator open/close tags
	wwwRegex                    = regexp.MustCompile(`(?i)www.`)       // removing www

	urlRegex = regexp.MustCompile(`^(?:(https?|ftp):\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^<>]*)?(?:\?[^<>]*)?(?:#[^<>]*)?(?:(!<script\b)[^<>])*$`) // url allowed characters and prevent attacks

	uriRegex = regexp.MustCompile(`[^:/?#\[\]@!$&'()*+,;=a-zA-Z0-9_~.%-]+`) // uri allowed characters

	scriptsRegex = regexp.MustCompile(`(?i)<(script|embed|object)[\S\s]*?>[\S\s]*?</(script|embed|object)>`) // Harmful html tags

	harmfulRegex = regexp.MustCompile(`(?i)\b(eval|fromCharCode|expression)\s*\(`) // javaScript functions we want to remove
)

var emptySpace = ""

// Alpha converts string to Alpha characters only
func Alpha(input string, spaces bool) string {
	// Leave white spaces?
	if spaces {
		return alphaWithSpacesRegex.ReplaceAllString(input, emptySpace)
	}

	// No spaces
	return alphaRegex.ReplaceAllString(input, emptySpace)
}

// AlphaNumeric converts string to AlphaNumerics characters only
func AlphaNumeric(input string, spaces bool) string {

	// Leave white spaces?
	if spaces {
		return alphaNumericWithSpacesRegex.ReplaceAllString(input, emptySpace)
	}

	// No spaces
	return alphaNumericRegex.ReplaceAllString(input, emptySpace)
}

// Domain checks if domain is valid and removes unnecessary characters
func Domain(input string, removeWww bool) (string, error) {

	// Try to see if we have a host
	if len(input) == 0 {
		return input, nil
	}

	//  Sanitize xss
	input = XSS(input)

	// Missing http?
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + strings.TrimSpace(input)
	}

	// Try to parse the urlStr
	u, err := url.Parse(input)
	if err != nil {
		return input, errors.New(fmt.Sprintf("invalid URL %v", err))
	}

	// Remove leading www.
	if removeWww {
		u.Host = wwwRegex.ReplaceAllString(u.Host, emptySpace)
	}

	// Add default port if missing
	if u.Port() == "" {
		switch u.Scheme {
		case "http":
			u.Host += ":80"
		case "https":
			u.Host += ":443"
		}
	}

	// Sanitize the path component
	u.Path = url.PathEscape(u.Path)

	// Reconstruct the URL
	urlStr := u.String()

	// Sanitized
	sanitizedUrl := domainRegex.ReplaceAllString(strings.ToLower(urlStr), emptySpace)

	// Checks if the sanitized struct matches the regex
	if !urlRegex.MatchString(sanitizedUrl) {
		return input, errors.New("invalid URL")
	}

	return sanitizedUrl, nil
}

// HTML Removes html/xml tags
func HTML(input string) string {
	return htmlRegex.ReplaceAllString(input, emptySpace)
}

// HtmlEscape escapes html characters
func HtmlEscape(input string) string {
	return html.EscapeString(input)
}

// Scripts removes scripts tags from string
func Scripts(input string) string {
	return scriptsRegex.ReplaceAllString(input, "")
}

// URI removes unnecessary characters from URI
func URI(input string) string {
	return uriRegex.ReplaceAllString(input, emptySpace)
}

// URL removes unnecessary characters from URL
func URL(input string) string {
	input = XSS(input)
	return urlRegex.ReplaceAllString(input, emptySpace)
}

// XML Removes xml tags
func XML(input string) string {
	return HTML(input)
}

// XSS protection against xss attacks
func XSS(input string) string {
	input = Scripts(input)
	input = strings.Replace(input, "eval(", "", -1)
	input = strings.Replace(input, "eval&#40;", "", -1)
	input = strings.Replace(input, "javascript:", "", -1)
	input = strings.Replace(input, "javascript&#58;", "", -1)
	input = strings.Replace(input, "fromCharCode", "", -1)
	input = strings.Replace(input, "&#62;", "", -1)
	input = strings.Replace(input, "&#60;", "", -1)
	input = strings.Replace(input, "&lt;", "", -1)
	input = strings.Replace(input, "&rt;", "", -1)
	input = HTML(input)
	return input
}

// SanitizeJS Takes in a string with js code and runs the code in a virtual machine to check if is harmful
func SanitizeJS(input string) (string, error) {
	vm := otto.New()

	// Define a function that we'll use to replace any instances of "eval(",
	// "fromCharCode(", or "expression(" with an empty string
	replaceFn := func(s string) string {
		return ""
	}

	// Replace any matches of the harmful regex with an empty string
	input = harmfulRegex.ReplaceAllStringFunc(input, replaceFn)

	// Use otto to evaluate the remaining JavaScript code
	_, err := vm.Run(input)
	if err != nil {
		return emptySpace, errors.New(fmt.Sprintf("Harmful JS code: %v", err))
	}

	// If the code evaluates successfully, return the sanitized JavaScript string
	sanitizedJS, _ := vm.Get("JSON.stringify(this)")
	return sanitizedJS.String(), nil
}
