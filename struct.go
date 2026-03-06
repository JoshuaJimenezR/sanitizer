package sanitizer

import (
	"errors"
	"fmt"
	"reflect"
)

type StructSanitizer struct {
	verbose bool
	tagName string
}

// Struct Sanitizes the given struct
func Struct(tagName string, any interface{}) error {
	ret := StructSanitizer{
		verbose: false,
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
			element := v.Field(i).Elem()

			if !v.Field(i).IsNil() && element.Kind() == reflect.Struct {
				if err := st.readStruct(element); err != nil {
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

		// Check if field is a Slice
		if v.Field(i).Kind() == reflect.Slice {
			if err := st.readSlice(v.Field(i), tagValue); err != nil {
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

// readSlice checks if a slice contains strings or structs to sanitize
func (st *StructSanitizer) readSlice(v reflect.Value, tagValue string) error {
	for j := 0; j < v.Len(); j++ {
		element := v.Index(j)

		if element.Kind() == reflect.Ptr {
			if !element.IsNil() && element.Elem().Kind() == reflect.Struct {
				if err := st.readStruct(element.Elem()); err != nil {
					return err
				}
			}
		} else if element.Kind() == reflect.Struct {
			if err := st.readStruct(element); err != nil {
				return err
			}
		} else if element.Kind() == reflect.String {
			if tagValue != "" {
				if st.verbose {
					fmt.Printf("Slice Element Sanitization Tag: %s \n", tagValue)
				}
				fieldValue, err := st.sanitizeString(tagValue, element.String())
				if err != nil {
					return err
				}
				if element.CanSet() {
					element.SetString(fieldValue)
				}
			}
		}
	}
	return nil
}

// checkFields checks if sanitization is possible
func (st *StructSanitizer) checkFields(tagValue string, v reflect.Value, i int, field reflect.StructField) error {
	if st.verbose {
		fmt.Printf("Field Name: %s, Field Value: %s, Field Sanitization Tag: %s \n", field.Name, v.Field(i).Interface(), tagValue)
	}

	//Sanitize strings
	if tagValue != "" {
		fieldValue, err := st.sanitizeString(tagValue, v.Field(i).String())
		if err != nil {
			return err
		}

		// Assign value to field
		v.Field(i).Set(reflect.ValueOf(fieldValue))
	}

	return nil
}

// sanitizeString sanitize field based on the given struct tag(xss, domain, url, uri)
func (st *StructSanitizer) sanitizeString(tagValue string, fieldValue string) (string, error) {

	// Sanitize Html
	if tagValue == htmlField {
		fieldValue = HTML(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize xml
	if tagValue == xmlField {
		fieldValue = XML(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Escape Html
	if tagValue == htmlEscapeField {
		fieldValue = HtmlEscape(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize scripts
	if tagValue == scriptsField {
		fieldValue = Scripts(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize url
	if tagValue == urlField {
		value, err := URL(fieldValue, true)
		if err != nil {
			return "", err
		}

		fieldValue = value

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize uri
	if tagValue == uriField {
		fieldValue = URI(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize Alpha with spaces
	if tagValue == alphaField {
		fieldValue = Alpha(fieldValue, true)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	// Sanitize AlphaNumeric with spaces
	if tagValue == alphanumericField {
		fieldValue = AlphaNumeric(fieldValue, true)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	//Sanitize XSS
	if tagValue == xssField {
		fieldValue = XSS(fieldValue)

		if st.verbose {
			fmt.Printf("Sanitized: %s\n", fieldValue)
		}
	}

	return fieldValue, nil
}
