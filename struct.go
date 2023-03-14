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

	if valueOf.Kind() != reflect.Pointer {
		fmt.Println("error struct needs to be a pointer")
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
		// Get the field
		field := t.Field(i)

		// Get the tag value
		tagValue := field.Tag.Get(st.tagName)

		// Check the data type
		switch field.Type.Kind() {
		case reflect.Struct:
			st.readStruct(v.Field(i))
		case reflect.String:
			//Sanitize strings
			if tagValue != "" {
				st.sanitizeFields(tagValue, v, i, field)
			}
		default:
			return
		}
	}

	return
}

func (st *StructSanitizer) sanitizeFields(tagValue string, v reflect.Value, i int, field reflect.StructField) {
	fieldValue := fmt.Sprintf("%v", reflect.ValueOf(v.Field(i)))

	//Sanitize Html
	if strings.Contains(tagValue, "html") {
		fieldValue = HTML(fieldValue)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Escape Html
	if strings.Contains(tagValue, "html_escape") {
		fieldValue = HtmlEscape(fieldValue)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize scripts
	if strings.Contains(tagValue, "scripts") {
		fieldValue = Scripts(fieldValue)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize domain
	if strings.Contains(tagValue, "domain") {
		fieldValue, _ = Domain(field.Name, false, false)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize url
	if strings.Contains(tagValue, "url") {
		fieldValue = URL(field.Name)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize uri
	if strings.Contains(tagValue, "uri") {
		fieldValue = URI(field.Name)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize Alpha with spaces
	if strings.Contains(tagValue, "alpha") {
		fieldValue = Alpha(field.Name, true)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize XSS
	if strings.Contains(tagValue, "xss") {
		fieldValue = XSS(fieldValue)

		if st.verbose {
			fmt.Printf("Field Name: %s\n", field.Name)
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Assign value to field
	v.Field(i).Set(reflect.ValueOf(fieldValue))
}
