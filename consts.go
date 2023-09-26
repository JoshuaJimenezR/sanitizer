package sanitizer

import "regexp"

// Regular Expression rules
var (
	alphaRegex                  = regexp.MustCompile("[^a-zA-Z]+")     // alpha characters
	alphaWithSpacesRegex        = regexp.MustCompile("[^a-zA-Z ]+")    // alpha characters with spaces
	alphaNumericRegex           = regexp.MustCompile("[^a-zA-Z0-9]+")  // alphanumeric characters
	alphaNumericWithSpacesRegex = regexp.MustCompile("[^a-zA-Z0-9 ]+") // alphanumeric characters with spaces
	htmlRegex                   = regexp.MustCompile(`<[^>]*>`)        // html/xml tags or any alligator open/close tags
	wwwRegex                    = regexp.MustCompile(`(?i)www.`)       // removing www

	urlRegex = regexp.MustCompile(`/^(?:https?:\/\/)?(?:www\.)?[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*(?:\:\d+)?(?:\/\S*)?$/`) // url allowed characters and prevent attacks

	uriRegex = regexp.MustCompile(`[^:/?#\[\]@!$&'()*+,;=a-zA-Z0-9_~.%-]+`) // uri allowed characters

	scriptsRegex = regexp.MustCompile(`(?i)<(script|iframe|embed|object)[^>]*>.*</(script|iframe|embed|object)>`) // Harmful script tags

	// harmfulRegex = regexp.MustCompile(`(?i)\b(eval|fromCharCode|expression)\s*\(`) // javaScript functions we want to remove

	emptySpace = ""

	htmlField         = "html"
	xmlField          = "xml"
	htmlEscapeField   = "html_escape"
	scriptsField      = "scripts"
	urlField          = "url"
	uriField          = "uri"
	alphaField        = "alpha"
	alphanumericField = "alphanumeric"
	xssField          = "xss"
)
