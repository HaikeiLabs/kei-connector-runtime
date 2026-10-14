package mcproute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// Limits on tools/call arguments (ADR-036 §4.5 step 8).
const (
	maxArgumentsBytes = 256 << 10
	maxArgumentsDepth = 32
)

const reasonInvalidArguments = "invalid_arguments"

// inputSchemaURI is the base URI an approved inputSchema is compiled under.
// It is never dereferenced: the compiler's loader refuses every URL.
const inputSchemaURI = "https://kei.invalid/mcp/input-schema.json"

// errNoExternalSchemas refuses every schema load. An approved inputSchema is
// untrusted upstream data, so a $ref or $schema must never make the daemon
// read a file or dial a URL. Only the bundled metaschemas resolve.
var errNoExternalSchemas = errors.New("external schema references are not loaded")

type refuseLoader struct{}

func (refuseLoader) Load(string) (any, error) { return nil, errNoExternalSchemas }

// validateArguments checks params.arguments of a tools/call against the
// verified inputSchema of tool: an object of at most 256 KiB, nested at most
// 32 levels, without duplicate keys, valid under JSON Schema 2020-12 unless
// the schema's $schema names another draft. Absent arguments are {}.
func (l *verifiedListing) validateArguments(tool string, params json.RawMessage) error {
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	args := bytes.TrimSpace(p.Arguments)
	if len(args) == 0 || bytes.Equal(args, []byte("null")) {
		args = []byte("{}")
	}
	if len(args) > maxArgumentsBytes {
		return fmt.Errorf("arguments exceed %d bytes", maxArgumentsBytes)
	}
	if args[0] != '{' {
		return errors.New("arguments must be an object")
	}
	if err := checkJSONShape(args, maxArgumentsDepth); err != nil {
		return err
	}
	schema, err := l.inputSchema(tool)
	if err != nil {
		return err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(args))
	if err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return schema.Validate(value)
}

// inputSchema compiles the tool's approved inputSchema once per listing.
func (l *verifiedListing) inputSchema(tool string) (*jsonschema.Schema, error) {
	l.schemaMu.Lock()
	defer l.schemaMu.Unlock()
	if s, ok := l.compiled[tool]; ok {
		return s, nil
	}
	raw, ok := l.schemas[tool]
	if !ok {
		return nil, errors.New("tool has no inputSchema")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("inputSchema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(refuseLoader{})
	if err := c.AddResource(inputSchemaURI, doc); err != nil {
		return nil, fmt.Errorf("inputSchema: %w", err)
	}
	s, err := c.Compile(inputSchemaURI)
	if err != nil {
		return nil, fmt.Errorf("inputSchema: %w", err)
	}
	if l.compiled == nil {
		l.compiled = make(map[string]*jsonschema.Schema)
	}
	l.compiled[tool] = s
	return s, nil
}

// checkJSONShape rejects a JSON value nested deeper than maxDepth objects
// and arrays, or holding an object with a duplicate key.
func checkJSONShape(data []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSON(dec, 0, maxDepth); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after arguments")
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth, maxDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth+1 > maxDepth {
		return fmt.Errorf("arguments nested deeper than %d levels", maxDepth)
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyTok.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			if err := walkJSON(dec, depth+1, maxDepth); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1, maxDepth); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}
