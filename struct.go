package sanitizer

import (
	"fmt"
	"reflect"
	"strings"
)

type StructSanitizer struct {
	verbose bool
	tagName string
}

func Struct(tagName string, any interface{}, verbose bool) {
	ret := StructSanitizer{
		verbose: verbose,
		tagName: tagName,
	}

	ret.SanitizeStruct(any)
}

func (st *StructSanitizer) SanitizeStruct(v interface{}) {
	valueOf := reflect.ValueOf(v)

	if valueOf.Kind() != reflect.Struct {
		return
	}

	st.readStruct(valueOf.Elem())
}

func (st *StructSanitizer) readStruct(v reflect.Value) {
	t := v.Type()
	numValues := t.NumField()

	// Empty struct
	if numValues == 0 {
		return
	}

	for i := 0; i < numValues; i++ {
		field := t.Field(i)
		tagValue := field.Tag.Get(st.tagName)

		//We need to include more data types
		switch field.Type.Kind() {
		case reflect.Struct:
			st.readStruct(v.Field(i))
		case reflect.String:
			st.sanitizeFields(tagValue, v, i, field)
		default:
			return
		}

	}

	fmt.Printf("%+v", v)

	return
}

func (st *StructSanitizer) sanitizeFields(tagValue string, v reflect.Value, i int, field reflect.StructField) {
	//Sanitize XSS
	v.Field(i).Set(reflect.ValueOf(XSS(field.Name)))

	if st.verbose {
		fmt.Printf("Field Name: %s\n", field.Name)
		fmt.Printf("Sanitized: %s\n", field.Name)
	}

	//Sanitize Html
	if strings.Contains(tagValue, "html") {
		v.Field(i).Set(reflect.ValueOf(HTML(field.Name)))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize Html
	if strings.Contains(tagValue, "html_escape") {
		v.Field(i).Set(reflect.ValueOf(HtmlEscape(field.Name)))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize domain
	if strings.Contains(tagValue, "domain") {
		domain, _ := Domain(field.Name, false, false)
		v.Field(i).Set(reflect.ValueOf(domain))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize url
	if strings.Contains(tagValue, "url") {
		v.Field(i).Set(reflect.ValueOf(URL(field.Name)))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize uri
	if strings.Contains(tagValue, "url") {
		v.Field(i).Set(reflect.ValueOf(URI(field.Name)))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize domain
	if strings.Contains(tagValue, "domainCase") {
		domain, _ := Domain(field.Name, true, false)
		v.Field(i).Set(reflect.ValueOf(domain))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize domain
	if strings.Contains(tagValue, "domainWww") {
		domain, _ := Domain(field.Name, false, true)
		v.Field(i).Set(reflect.ValueOf(domain))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	//Sanitize Alpha with no spaces
	if strings.Contains(tagValue, "alpha") {
		v.Field(i).Set(reflect.ValueOf(Alpha(field.Name, false)))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

	// Sanitize Alpha with spaces
	if strings.Contains(tagValue, "alphaSpaces") {
		v.Field(i).Set(reflect.ValueOf(Alpha(field.Name, true)))

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", field.Name)
		}
	}

}
