package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"azops-cli/internal/domain"
	"gopkg.in/yaml.v3"
)

func decodeFile(path string, output any) error {
	file, err := os.Open(path)
	if err != nil {
		return &domain.DiscoveryError{Path: path, Err: err}
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(output); err != nil {
		return decodeError(path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return decodeError(path, err)
		}
		return &domain.DecodeError{Path: path, Err: errors.New("multiple YAML documents are unsupported")}
	}
	return nil
}

func decodeError(path string, err error) error {
	field := ""
	message := err.Error()
	if index := strings.Index(message, "line "); index >= 0 {
		field = strings.TrimSpace(message[index:])
	}
	return &domain.DecodeError{Path: path, Field: field, Err: fmt.Errorf("invalid YAML: %w", err)}
}
