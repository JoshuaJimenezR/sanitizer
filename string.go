package sanitizer

type StringSanitizer struct {
	html       bool
	htmlEscape bool
	xss        bool
}

var (
	DefaultSanitizer = &StringSanitizer{
		html:       true,
		htmlEscape: true,
		xss:        true,
	}
)

func String() *StringSanitizer {
	return DefaultSanitizer
}

func (st *StringSanitizer) Plain(original string) string {
	if st.html {
		original = HTML(original)
	}

	if st.htmlEscape {
		original = HtmlEscape(original)
	}

	if st.xss {
		original = XSS(original)
	}

	return original
}

func (st *StringSanitizer) Domain(original string, preserveCase, removeWww bool) (string, error) {
	original = st.Plain(original)

	return Domain(original, preserveCase, removeWww)
}

func (st *StringSanitizer) SliceOfStr(original []string) []string {
	for i := 0; i < len(original); i++ {
		original[i] = st.Plain(original[i])
	}

	return original
}

func (st *StringSanitizer) MapOfStr(original map[interface{}]string) map[interface{}]string {
	for _, v := range original {
		v = st.Plain(v)
	}
	return original
}
