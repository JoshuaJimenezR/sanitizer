package sanitizer

import (
	"fmt"
	"html"
	"net/url"
	"strings"
)

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
func URL(input string, removeWww bool) (string, error) {
	// Missing http?
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + strings.TrimSpace(input)
	}

	// Try to parse the urlStr
	u, err := url.Parse(input)
	if err != nil {
		return input, fmt.Errorf("invalid URL %v", err)
	}

	if removeWww {
		u.Host = wwwRegex.ReplaceAllString(u.Host, emptySpace)
	}

	return u.String(), nil
}

// XML Removes xml tags
func XML(input string) string {
	return HTML(input)
}

// XSS protection against xss attacks
func XSS(input string) string {
	input = Scripts(input)
	input = xssEvalRegex.ReplaceAllString(input, "")
	input = xssJavascriptRegex.ReplaceAllString(input, "")
	input = xssFromCharCodeRegex.ReplaceAllString(input, "")
	input = strings.Replace(input, "&#62;", "", -1)
	input = strings.Replace(input, "&#60;", "", -1)
	input = strings.Replace(input, "&lt;", "", -1)
	input = strings.Replace(input, "&gt;", "", -1) // Fixed html entity greater-than
	input = HTML(input)
	return input
}
