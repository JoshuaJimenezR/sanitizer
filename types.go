package sanitizer

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

// Regular Expression rules
var (
	alphaNumericRegExp           = regexp.MustCompile(`[^a-zA-Z0-9]`) // Alpha numeric
	alphaNumericWithSpacesRegExp = regexp.MustCompile(`[^a-zA-Z0-9\s]`)
	alphaRegExp                  = regexp.MustCompile(`[^a-zA-Z]`)                                                                // Alpha characters
	alphaWithSpacesRegExp        = regexp.MustCompile(`[^a-zA-Z\s]`)                                                              // Alpha characters (with spaces)// Alphanumeric (with spaces)
	domainRegExp                 = regexp.MustCompile(`[^a-zA-Z0-9-.]`)                                                           // Domain accepted characters
	htmlRegExp                   = regexp.MustCompile(`(?i)<[^>]*>`)                                                              // HTML/XML tags or any alligator open/close tags
	scriptRegExp                 = regexp.MustCompile(`(?i)<(script|iframe|embed|object)[^>]*>.*</(script|iframe|embed|object)>`) // Scripts and embeds
	uriRegExp                    = regexp.MustCompile(`[^a-zA-Z0-9-_/?&=#%]`)                                                     // URI allowed characters
	urlRegExp                    = regexp.MustCompile(`[^a-zA-Z0-9-_/:.,?&@=#%]`)                                                 // URL allowed characters
	wwwRegExp                    = regexp.MustCompile(`(?i)www.`)                                                                 // For removing www
)

var emptySpace = []byte("")

// Alpha converts string to Alpha characters only
func Alpha(original string, spaces bool) string {
	// Leave white spaces?
	if spaces {
		return string(alphaWithSpacesRegExp.ReplaceAll([]byte(original), emptySpace))
	}

	// No spaces
	return string(alphaRegExp.ReplaceAll([]byte(original), emptySpace))
}

// AlphaNumeric converts string to AlphaNumerics characters only
func AlphaNumeric(original string, spaces bool) string {

	// Leave white spaces?
	if spaces {
		return string(alphaNumericWithSpacesRegExp.ReplaceAll([]byte(original), emptySpace))
	}

	// No spaces
	return string(alphaNumericRegExp.ReplaceAll([]byte(original), emptySpace))
}

// Domain checks if domain is valid and removes unnecessary characters
func Domain(original string, preserveCase bool, removeWww bool) (string, error) {

	// Try to see if we have a host
	if len(original) == 0 {
		return original, nil
	}

	// Missing http?
	if !strings.Contains(original, "http") {
		original = "http://" + strings.TrimSpace(original)
	}

	// Try to parse the url
	u, err := url.Parse(original)
	if err != nil {
		return original, err
	}

	// Remove leading www.
	if removeWww {
		u.Host = wwwRegExp.ReplaceAllString(u.Host, "")
	}

	// Keeps the exact case of the original input string
	if preserveCase {
		return string(domainRegExp.ReplaceAll([]byte(u.Host), emptySpace)), nil
	}

	// Generally all domains should be uniform and lowercase
	return string(domainRegExp.ReplaceAll([]byte(strings.ToLower(u.Host)), emptySpace)), nil
}

// HTML Removes html/xml tags
func HTML(original string) string {
	return string(htmlRegExp.ReplaceAll([]byte(original), emptySpace))
}

// HtmlEscape escapes html characters
func HtmlEscape(original string) string {
	return html.EscapeString(original)
}

// Scripts removes scripts tags from string
func Scripts(original string) string {
	return string(scriptRegExp.ReplaceAll([]byte(original), emptySpace))
}

// URI removes unnecessary characters from URI
func URI(original string) string {
	return string(uriRegExp.ReplaceAll([]byte(original), emptySpace))
}

// URL removes unnecessary characters from URL
func URL(original string) string {
	return string(urlRegExp.ReplaceAll([]byte(original), emptySpace))
}

// XML Removes xml tags
func XML(original string) string {
	return HTML(original)
}

// XSS protection against xss attacks
func XSS(original string) string {
	original = Scripts(original)
	original = strings.Replace(original, "eval(", "", -1)
	original = strings.Replace(original, "eval&#40;", "", -1)
	original = strings.Replace(original, "javascript:", "", -1)
	original = strings.Replace(original, "javascript&#58;", "", -1)
	original = strings.Replace(original, "fromCharCode", "", -1)
	original = strings.Replace(original, "&#62;", "", -1)
	original = strings.Replace(original, "&#60;", "", -1)
	original = strings.Replace(original, "&lt;", "", -1)
	original = strings.Replace(original, "&rt;", "", -1)
	original = HTML(original)
	return original
}
