package connectorruntime

import (
	"embed"
	"encoding/json"

	bundle "github.com/HaikeiLabs/kei-connector-contracts/bundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/policybundle"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed docs/contracts/policy-bundle-v1.schema.json docs/contracts/policy-set-v1.schema.json docs/contracts/policy-bundle-v2.schema.json docs/contracts/policy-set-v2.schema.json
var policySchemas embed.FS

func init() {
	policybundle.SetSchemaValidator(validatePolicyBundleSchema)
	policybundle.SetV2SchemaValidator(validatePolicyBundleV2Schema)
	bundle.SetPlanValidator(policybundle.ValidateV2Plan)
}

func validatePolicyBundleSchema(raw []byte) error {
	bundleBytes, err := policySchemas.ReadFile("docs/contracts/policy-bundle-v1.schema.json")
	if err != nil {
		return err
	}
	setBytes, err := policySchemas.ReadFile("docs/contracts/policy-set-v1.schema.json")
	if err != nil {
		return err
	}
	var bundleDoc, setDoc, doc any
	if err := json.Unmarshal(bundleBytes, &bundleDoc); err != nil {
		return err
	}
	if err := json.Unmarshal(setBytes, &setDoc); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v1.schema.json", setDoc); err != nil {
		return err
	}
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v1.schema.json", bundleDoc); err != nil {
		return err
	}
	s, err := c.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v1.schema.json")
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

func validatePolicyBundleV2Schema(raw []byte) error {
	load := func(name string) (any, error) {
		b, err := policySchemas.ReadFile("docs/contracts/" + name)
		if err != nil {
			return nil, err
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
		return doc, nil
	}
	bundleDoc, err := load("policy-bundle-v2.schema.json")
	if err != nil {
		return err
	}
	setDoc, err := load("policy-set-v2.schema.json")
	if err != nil {
		return err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-set-v2.schema.json", setDoc); err != nil {
		return err
	}
	if err := c.AddResource("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json", bundleDoc); err != nil {
		return err
	}
	s, err := c.Compile("https://schemas.haikeilabs.com/kei/policy-bundle-v2.schema.json")
	if err != nil {
		return err
	}
	return s.Validate(doc)
}
