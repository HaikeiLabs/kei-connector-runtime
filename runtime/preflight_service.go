package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

var ErrBundlePlanUnavailable = errors.New("validated bundle operation plan unavailable")

type preflightService struct{ store *AuthorizationStore }

func newPreflightService() *preflightService {
	return &preflightService{store: NewAuthorizationStore()}
}

type bundlePlanInterpreter struct{ tool policybundle.V2Tool }

func (p bundlePlanInterpreter) Plan(argsRaw, contextRaw []byte, _ BindingContext) ([]Operation, error) {
	argsRaw, contextRaw, err := policybundle.ValidatePlanData(p.tool, argsRaw, contextRaw)
	if err != nil {
		return nil, ErrPlanInvalid
	}
	plan, err := policybundle.ParseV2Plan(p.tool)
	if err != nil {
		return nil, ErrPlanInvalid
	}
	args, err := decodePlanObject(argsRaw)
	if err != nil {
		return nil, ErrPlanInvalid
	}
	context, err := decodePlanObject(contextRaw)
	if err != nil {
		return nil, ErrPlanInvalid
	}
	ops := make([]Operation, 0, len(plan.Operations))
	for _, template := range plan.Operations {
		var resource, resourceType, resourceText, parentText, parentKind string
		if template.Resource != nil {
			resourceType = template.Resource.Type
			if template.Resource.Parent != nil {
				parentKind = template.Resource.Parent.Type
			}
			var ok bool
			if template.Resource.ID != nil {
				value, found := resolvePlanValue(*template.Resource.ID, args, context)
				if !found {
					return nil, ErrPlanInvalid
				}
				resourceText, ok = planScalarString(value, false, template.Resource.Type)
				if !ok {
					return nil, ErrPlanInvalid
				}
			}
			if template.Resource.Parent != nil {
				value, found := resolvePlanValue(*template.Resource.Parent.ID, args, context)
				if !found {
					return nil, ErrPlanInvalid
				}
				parentText, ok = planScalarString(value, true, template.Resource.Parent.Type)
				if !ok {
					return nil, ErrPlanInvalid
				}
			}
			var valid bool
			resource, valid = renderProviderResource(template.ProviderResourceTemplate, resourceText, parentText)
			if !valid {
				return nil, ErrPlanInvalid
			}
		} else {
			var valid bool
			resource, valid = renderProviderResource(template.ProviderResourceTemplate, "", "")
			if !valid {
				return nil, ErrPlanInvalid
			}
		}
		var providerInputTemplate any
		inputDecoder := json.NewDecoder(bytes.NewReader(template.ProviderInput))
		inputDecoder.UseNumber()
		if inputDecoder.Decode(&providerInputTemplate) != nil {
			return nil, ErrPlanInvalid
		}
		providerInputValue, err := materializePlanTemplate(providerInputTemplate, args, context, 0)
		if err != nil {
			return nil, ErrPlanInvalid
		}
		if _, ok := providerInputValue.(map[string]any); !ok {
			return nil, ErrPlanInvalid
		}
		providerInputNodes := 0
		if !planValueWithinBounds(providerInputValue, 0, &providerInputNodes) {
			return nil, ErrPlanInvalid
		}
		providerInput, err := jsonMarshalCanonical(providerInputValue)
		if err != nil || len(providerInput) > policybundle.MaxPlanProviderInputBytes {
			return nil, ErrPlanInvalid
		}
		action, ok := registeredCapabilityAction(p.tool.Source, template.Capability)
		if !ok {
			return nil, ErrPlanInvalid
		}
		ops = append(ops, Operation{ID: template.ID, ConnectorID: p.tool.Route.ConnectorBinding.ConnectorID, Capability: template.Capability, Action: action, Resource: resource, InputDigest: operationInputDigest(providerInput), ProviderInput: providerInput, ResourceType: resourceType, ResourceID: resourceText, ResourceParent: parentText, ResourceParentType: parentKind})
	}
	return ops, nil
}

func (l *LocalPDP) PreflightV2(ctx context.Context, toolName, agentID string, argsRaw, contextRaw []byte, parentSpan string, depth int, ttl time.Duration) (PreflightResult, error) {
	if ctx.Err() != nil || l.preflight == nil {
		return PreflightResult{}, ErrPreflightDenied
	}
	binding, tool, args, contextValues, err := l.preflightBinding(toolName, agentID, argsRaw, contextRaw, parentSpan, depth)
	if err != nil {
		return PreflightResult{}, ErrPreflightDenied
	}
	result, err := l.preflight.store.Preflight(PreflightInput{Binding: binding, ValidatedArgs: args, ValidatedContext: contextValues, Planner: bundlePlanInterpreter{tool}, Authorizer: l}, ttl)
	if err != nil {
		return PreflightResult{}, err
	}
	return result, nil
}

func (l *LocalPDP) PlanV2(ctx context.Context, toolName, agentID string, argsRaw, contextRaw []byte, parentSpan string, depth int) (BindingContext, []Operation, error) {
	if ctx.Err() != nil || l.preflight == nil {
		return BindingContext{}, nil, ErrPreflightDenied
	}
	binding, tool, args, contextValues, err := l.preflightBinding(toolName, agentID, argsRaw, contextRaw, parentSpan, depth)
	if err != nil {
		return BindingContext{}, nil, ErrPreflightDenied
	}
	ops, err := (bundlePlanInterpreter{tool}).Plan(args, contextValues, binding)
	if err != nil || validatePlan(binding.Route, ops) != nil {
		return BindingContext{}, nil, ErrPlanInvalid
	}
	return binding, cloneOperations(ops), nil
}

func (l *LocalPDP) ValidateV2Plan(ctx context.Context, handle, toolName, agentID string, argsRaw, contextRaw []byte, ops []Operation, parentSpan string, depth int) error {
	if ctx.Err() != nil || l.preflight == nil {
		return ErrAuthorizationInvalid
	}
	binding, _, _, _, err := l.preflightBinding(toolName, agentID, argsRaw, contextRaw, parentSpan, depth)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	return l.preflight.store.ValidatePlan(handle, binding, ops, l)
}

func (l *LocalPDP) ConsumeV2(ctx context.Context, handle, toolName, agentID string, argsRaw, contextRaw []byte, op Operation, parentSpan string, depth int) error {
	if ctx.Err() != nil || l.preflight == nil {
		return ErrAuthorizationInvalid
	}
	binding, _, _, _, err := l.preflightBinding(toolName, agentID, argsRaw, contextRaw, parentSpan, depth)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	return l.preflight.store.Consume(handle, binding, op, l)
}

func (l *LocalPDP) ConsumeV2Plan(ctx context.Context, handle, toolName, agentID string, argsRaw, contextRaw []byte, ops []Operation, parentSpan string, depth int) error {
	if ctx.Err() != nil || l.preflight == nil {
		return ErrAuthorizationInvalid
	}
	binding, _, _, _, err := l.preflightBinding(toolName, agentID, argsRaw, contextRaw, parentSpan, depth)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	return l.preflight.store.ConsumePlan(handle, binding, ops, l)
}

func (l *LocalPDP) DescribeV2Tool(toolName, agentID string) (provider, connectorID string, capabilities []string, subject, trustedAgentID string, tenantID, workspaceID string, ok bool) {
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil || identity.WorkspaceID == nil || agentID == "" {
		return "", "", nil, "", "", "", "", false
	}
	ctx, found := e.V2PlanContext(toolName)
	if !found || ctx.Tool.Route.ConnectorBinding == nil {
		return "", "", nil, "", "", "", "", false
	}
	session, found := l.Sessions.Current()
	if !found || session.Status != pdp.StatusLinked || session.UserID == "" {
		return "", "", nil, "", "", "", "", false
	}
	return ctx.Tool.Source, ctx.Tool.Route.ConnectorBinding.ConnectorID, append([]string(nil), ctx.Tool.RequiredCapabilities...), session.UserID, agentID, identity.OrgID, *identity.WorkspaceID, true
}

func (l *LocalPDP) AuthorizePlan(binding BindingContext, ops []Operation) (string, int64, bool, error) {
	e := l.evaluator.Load()
	if e == nil || l.identity.Load() == nil {
		return "", 0, false, nil
	}
	ctx, ok := e.V2PlanContext(binding.Tool)
	if !ok || !bundleToolMatchesBinding(ctx.Tool, binding) {
		return "", 0, false, nil
	}
	return e.AuthorizeV2Plan(binding.InstallationID, binding.Subject, binding.SubjectSource, binding.SubjectExternalID, binding.AgentID, binding.Tool, ops)
}

func (l *LocalPDP) preflightBinding(toolName, agentID string, argsRaw, contextRaw []byte, parentSpan string, depth int) (BindingContext, policybundle.V2Tool, []byte, []byte, error) {
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil || identity.WorkspaceID == nil {
		return BindingContext{}, policybundle.V2Tool{}, nil, nil, ErrPreflightDenied
	}
	planContext, ok := e.V2PlanContext(toolName)
	if !ok || planContext.Tool.Route.ConnectorBinding == nil {
		return BindingContext{}, policybundle.V2Tool{}, nil, nil, ErrBundlePlanUnavailable
	}
	if agentID == "" {
		return BindingContext{}, policybundle.V2Tool{}, nil, nil, ErrPreflightDenied
	}
	args, contextValues, err := policybundle.ValidatePlanData(planContext.Tool, argsRaw, contextRaw)
	if err != nil {
		return BindingContext{}, policybundle.V2Tool{}, nil, nil, ErrPlanInvalid
	}
	subject, ok := l.Sessions.Current()
	if !ok || subject.Status != pdp.StatusLinked || subject.UserID == "" {
		return BindingContext{}, policybundle.V2Tool{}, nil, nil, ErrPreflightDenied
	}
	connectorID := planContext.Tool.Route.ConnectorBinding.ConnectorID
	caps := append([]string(nil), planContext.Tool.RequiredCapabilities...)
	binding := BindingContext{
		InstallationID: identity.ID, BundleVersion: planContext.BundleVersion, BundleDigest: planContext.BundleDigest,
		ArgsDigest: operationInputDigest(args), ContextDigest: operationInputDigest(contextValues),
		Subject: subject.UserID, SubjectSource: subject.Source, SubjectExternalID: subject.ExternalID,
		AgentID: agentID, Tool: toolName, Route: ConnectorDispatch{Provider: planContext.Tool.Source, ConnectorID: connectorID, RequiredCapabilities: caps},
		ParentSpan: parentSpan, DelegationDepth: depth,
	}
	return binding, planContext.Tool, args, contextValues, nil
}

func bundleToolMatchesBinding(tool policybundle.V2Tool, binding BindingContext) bool {
	route, ok := binding.Route.(ConnectorDispatch)
	return ok && tool.Name == binding.Tool && tool.Plan != nil && tool.Route.ConnectorBinding != nil && tool.Source == route.Provider && tool.Route.ConnectorBinding.ConnectorID == route.ConnectorID && equalStrings(tool.RequiredCapabilities, route.RequiredCapabilities)
}
