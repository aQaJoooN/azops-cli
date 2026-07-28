package report

import (
	"reflect"
	"sort"
	"strings"
)

const replacement = "[REDACTED]"

// Redactor replaces known PAT and secret strings in human-readable output.
type Redactor struct {
	replacer *strings.Replacer
}

// NewRedactor builds a redactor from the PAT and all non-empty string scalars in secrets.
func NewRedactor(pat string, secrets any) Redactor {
	values := make(map[string]struct{})
	addValue(values, pat)
	collectStrings(reflect.ValueOf(secrets), values)

	ordered := make([]string, 0, len(values))
	for value := range values {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	pairs := make([]string, 0, len(ordered)*2)
	for _, value := range ordered {
		pairs = append(pairs, value, replacement)
	}
	if len(pairs) == 0 {
		return Redactor{}
	}
	return Redactor{replacer: strings.NewReplacer(pairs...)}
}

// Redact replaces exact occurrences of known sensitive values.
func (r Redactor) Redact(value string) string {
	if r.replacer == nil {
		return value
	}
	return r.replacer.Replace(value)
}

func addValue(values map[string]struct{}, value string) {
	if value != "" {
		values[value] = struct{}{}
	}
}

func collectStrings(value reflect.Value, values map[string]struct{}) {
	if !value.IsValid() {
		return
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if !value.IsNil() {
			collectStrings(value.Elem(), values)
		}
		return
	}
	switch value.Kind() {
	case reflect.String:
		addValue(values, value.String())
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			collectStrings(value.Field(i), values)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			collectStrings(value.Index(i), values)
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			collectStrings(iterator.Key(), values)
			collectStrings(iterator.Value(), values)
		}
	}
}
