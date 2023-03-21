package sanitizer

import (
	"errors"
	"fmt"
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

	scriptsRegex = regexp.MustCompile(`(?i)<(script|embed|object)[\S\s]*?>[\S\s]*?</(script|embed|object)>`) // Harmful script tags

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

	return domainRegex.ReplaceAllString(strings.ToLower(urlStr), emptySpace), nil
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
	return input
}
