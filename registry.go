package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Registry struct {
	Tools map[string]string `yaml:"tools"`
}

func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load registry %s: %w", path, err)
	}

	var reg Registry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse registry %s: %w", path, err)
	}
	if reg.Tools == nil {
		reg.Tools = map[string]string{}
	}

	return &reg, nil
}

func (r *Registry) Service(tool string) string {
	return r.Tools[tool]
}
