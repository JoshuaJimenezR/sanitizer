package sanitizer

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type StructSanitizer struct {
	verbose bool
	tagName string
}

// Struct Sanitizes the given struct
func Struct(tagName string, any interface{}, verbose bool) error {
	ret := StructSanitizer{
		verbose: verbose,
		tagName: tagName,
	}

	err := ret.SanitizeStruct(any)
	if err != nil {
		return err
	}

	return nil
}

// SanitizeStruct Checks the given interface
func (st *StructSanitizer) SanitizeStruct(any interface{}) error {
	// read value of interface
	v := reflect.ValueOf(any)

	// check if struct is a pointer
	if v.Kind() != reflect.Pointer {
		return errors.New("struct needs to be a pointer")
	}

	// pointer value
	value := v.Elem()

	//Check number of fields
	t := value.Type()
	numValues := t.NumField()

	// Empty struct
	if numValues == 0 {
		return errors.New("struct is empty")
	}

	// Read struct
	err := st.readStruct(value)
	if err != nil {
		return err
	}

	return nil
}

// readStruct Recursive Read struct fields
func (st *StructSanitizer) readStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		// Get the field
		field := v.Type().Field(i)
		tag := field.Tag

		// Get the tag value
		tagValue := tag.Get(st.tagName)

		// Check if field is a Pointer
		if v.Field(i).Kind() == reflect.Ptr {
			if !v.Field(i).IsNil() {
				if err := st.readStruct(v.Field(i).Elem()); err != nil {
					return err
				}
			}
			continue
		}

		// Check if field is a Pointer
		if v.Field(i).Kind() == reflect.Struct {
			if err := st.readStruct(v.Field(i)); err != nil {
				return err
			}
			continue
		}

		// Check if field is a string
		if v.Field(i).Kind() == reflect.String {
			if err := st.checkFields(tagValue, v, i, field); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkFields checks if sanitization is possible
func (st *StructSanitizer) checkFields(tagValue string, v reflect.Value, i int, field reflect.StructField) error {
	if st.verbose {
		fmt.Printf("Field Name: %s, Field Value: %s, Field Sanitization Tag: %s \n", field.Name, reflect.ValueOf(field), tagValue)
	}

	//Sanitize strings
	if tagValue != "" {
		fieldValue, err := st.sanitizeFields(tagValue, v, i, field)
		if err != nil {
			return err
		}

		// Assign value to field
		v.Field(i).Set(reflect.ValueOf(fieldValue))
	}

	return nil
}

// sanitizeFields sanitize fields based on the given struct tag(xss, domain, url, uri
func (st *StructSanitizer) sanitizeFields(tagValue string, v reflect.Value, i int, field reflect.StructField) (string, error) {
	fieldValue := fmt.Sprintf("%v", reflect.ValueOf(v.Field(i)))

	//Sanitize Html
	if strings.Contains(tagValue, "html") {
		fieldValue = HTML(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	if strings.Contains(tagValue, "xml") {
		fieldValue = XML(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Escape Html
	if strings.Contains(tagValue, "html_escape") {
		fieldValue = HtmlEscape(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize scripts
	if strings.Contains(tagValue, "scripts") {
		fieldValue = Scripts(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize domain
	if strings.Contains(tagValue, "domain") {
		domainResp, err := Domain(field.Name, false)
		if err != nil {
			return fieldValue, err
		}

		fieldValue = domainResp

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize url
	if strings.Contains(tagValue, "url") {
		fieldValue = URL(field.Name)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize uri
	if strings.Contains(tagValue, "uri") {
		fieldValue = URI(field.Name)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize Alpha with spaces
	if strings.Contains(tagValue, "alpha") {
		fieldValue = Alpha(field.Name, true)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize XSS
	if strings.Contains(tagValue, "xss") {
		fieldValue = XSS(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	return fieldValue, nil
}
