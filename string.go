package sanitizer

type StringSanitizer struct {
	Alpha        bool
	AlphaNumeric bool
	Domain       bool
	HTML         bool
	HTMLEscape   bool
	URI          bool
	URL          bool
	XML          bool
	XSS          bool
}

func StringWithOptions(original string, sanitizer StringSanitizer) string {
	if sanitizer.Alpha {
		original = Alpha(original, true)
	}

	if sanitizer.AlphaNumeric {
		original = AlphaNumeric(original, true)
	}

	if sanitizer.Domain {
		original, _ = Domain(original, true)
	}

	if sanitizer.HTML {
		original = HTML(original)
	}

	if sanitizer.HTMLEscape {
		original = HtmlEscape(original)
	}

	if sanitizer.XSS {
		original = XSS(original)
	}

	return original
}

func SliceOfStr(original []string, sanitizer StringSanitizer) []string {
	for i := 0; i < len(original); i++ {
		original[i] = StringWithOptions(original[i], sanitizer)
	}

	return original
}

func MapOfStr(original map[interface{}]string, sanitizer StringSanitizer) map[interface{}]string {
	for _, v := range original {
		v = StringWithOptions(v, sanitizer)
	}
	return original
}
