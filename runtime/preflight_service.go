package runtime

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
	"github.com/HaikeiLabs/kei-connector-runtime/pkg/pdp"
)

var ErrPlannerUnavailable = errors.New("trusted operation planner unavailable")

type registeredPlanner struct {
	definition ToolDefinition
	planner    OperationPlanner
}

type preflightService struct {
	store    *AuthorizationStore
	mu       sync.RWMutex
	planners map[string]registeredPlanner
}

func newPreflightService() *preflightService {
	return &preflightService{store: NewAuthorizationStore(), planners: make(map[string]registeredPlanner)}
}

// RegisterOperationPlanner binds trusted local registration metadata to code
// that derives complete plans from validated tool arguments. No socket payload
// can register or replace a planner.
func (l *LocalPDP) RegisterOperationPlanner(definition ToolDefinition, planner OperationPlanner) error {
	if planner == nil || validateToolRoute(definition, "tool") != nil || definition.Route == nil || definition.Route.ConnectorBinding == nil {
		return ErrPlannerUnavailable
	}
	if l.preflight == nil {
		return ErrPlannerUnavailable
	}
	definition.RequiredCapabilities = append([]string(nil), definition.RequiredCapabilities...)
	definition.ResourceTypes = append([]KeiResourceType(nil), definition.ResourceTypes...)
	l.preflight.mu.Lock()
	defer l.preflight.mu.Unlock()
	if _, exists := l.preflight.planners[definition.Name]; exists {
		return ErrPlannerUnavailable
	}
	l.preflight.planners[definition.Name] = registeredPlanner{definition: definition, planner: planner}
	return nil
}

func (l *LocalPDP) PreflightV2(ctx context.Context, toolName, agentID string, validatedArgs []byte, parentSpan string, depth int, ttl time.Duration) (PreflightResult, error) {
	if err := ctx.Err(); err != nil || l.preflight == nil {
		return PreflightResult{}, ErrPreflightDenied
	}
	binding, reg, err := l.preflightBinding(toolName, agentID, parentSpan, depth)
	if err != nil {
		return PreflightResult{}, ErrPreflightDenied
	}
	if len(validatedArgs) > input.MaxBytes {
		return PreflightResult{}, ErrPlanInvalid
	}
	canonical, _, err := input.Canonicalize(validatedArgs)
	if err != nil {
		return PreflightResult{}, ErrPlanInvalid
	}
	result, err := l.preflight.store.Preflight(PreflightInput{Binding: binding, ValidatedArgs: canonical, Planner: reg.planner, Authorizer: l}, ttl)
	if err != nil {
		return PreflightResult{}, err
	}
	return result, nil
}

func (l *LocalPDP) PlanV2(ctx context.Context, toolName, agentID string, validatedArgs []byte, parentSpan string, depth int) (BindingContext, []Operation, error) {
	if err := ctx.Err(); err != nil || l.preflight == nil {
		return BindingContext{}, nil, ErrPreflightDenied
	}
	binding, reg, err := l.preflightBinding(toolName, agentID, parentSpan, depth)
	if err != nil {
		return BindingContext{}, nil, ErrPreflightDenied
	}
	if len(validatedArgs) > input.MaxBytes {
		return BindingContext{}, nil, ErrPlanInvalid
	}
	canonical, _, err := input.Canonicalize(validatedArgs)
	if err != nil {
		return BindingContext{}, nil, ErrPlanInvalid
	}
	ops, err := reg.planner.Plan(append([]byte(nil), canonical...), cloneBinding(binding))
	if err != nil || validatePlan(binding.Route, ops) != nil {
		return BindingContext{}, nil, ErrPlanInvalid
	}
	expectedDigest := operationInputDigest(canonical)
	for _, op := range ops {
		if op.InputDigest != expectedDigest {
			return BindingContext{}, nil, ErrPlanInvalid
		}
	}
	return binding, cloneOperations(ops), nil
}

func (l *LocalPDP) ValidateV2Plan(ctx context.Context, handle, toolName, agentID string, ops []Operation, parentSpan string, depth int) error {
	if err := ctx.Err(); err != nil || l.preflight == nil {
		return ErrAuthorizationInvalid
	}
	binding, _, err := l.preflightBinding(toolName, agentID, parentSpan, depth)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	return l.preflight.store.ValidatePlan(handle, binding, ops, l)
}

func (l *LocalPDP) ConsumeV2(ctx context.Context, handle, toolName, agentID string, op Operation, parentSpan string, depth int) error {
	if err := ctx.Err(); err != nil || l.preflight == nil {
		return ErrAuthorizationInvalid
	}
	binding, _, err := l.preflightBinding(toolName, agentID, parentSpan, depth)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	return l.preflight.store.Consume(handle, binding, op, l)
}

func (l *LocalPDP) DescribeV2Tool(toolName, agentID string) (provider, connectorID string, capabilities []string, subject, trustedAgentID string, tenantID, workspaceID string, ok bool) {
	binding, reg, err := l.preflightBinding(toolName, agentID, "", 0)
	if err != nil {
		return "", "", nil, "", "", "", "", false
	}
	identity := l.identity.Load()
	if identity == nil || identity.WorkspaceID == nil {
		return "", "", nil, "", "", "", "", false
	}
	agentID = reg.definition.Route.ConnectorBinding.AgentID
	return reg.definition.Source, binding.Route.(ConnectorDispatch).ConnectorID, append([]string(nil), reg.definition.RequiredCapabilities...), binding.Subject, agentID, identity.OrgID, *identity.WorkspaceID, true
}

func (l *LocalPDP) AuthorizePlan(binding BindingContext, ops []Operation) (string, int64, bool, error) {
	e := l.evaluator.Load()
	if e == nil || l.identity.Load() == nil {
		return "", 0, false, nil
	}
	reg, ok := l.registeredPlanner(binding.Tool)
	if !ok || !registrationMatchesBinding(reg.definition, binding) {
		return "", 0, false, nil
	}
	return e.AuthorizeV2Plan(binding.InstallationID, binding.Subject, binding.SubjectSource, binding.SubjectExternalID, binding.AgentID, binding.Tool, ops)
}

func (l *LocalPDP) preflightBinding(toolName, agentID, parentSpan string, depth int) (BindingContext, registeredPlanner, error) {
	reg, ok := l.registeredPlanner(toolName)
	if !ok || reg.definition.Route == nil || reg.definition.Route.ConnectorBinding == nil {
		return BindingContext{}, registeredPlanner{}, ErrPlannerUnavailable
	}
	e, identity := l.evaluator.Load(), l.identity.Load()
	if e == nil || identity == nil || identity.WorkspaceID == nil {
		return BindingContext{}, registeredPlanner{}, ErrPreflightDenied
	}
	if agentID == "" {
		agentID = reg.definition.Route.ConnectorBinding.AgentID
	}
	if agentID != reg.definition.Route.ConnectorBinding.AgentID {
		return BindingContext{}, registeredPlanner{}, ErrPreflightDenied
	}
	ctx, ok := e.V2PlanContext(toolName)
	if !ok || !bundleToolMatchesRegistration(ctx.Tool, reg.definition) {
		return BindingContext{}, registeredPlanner{}, ErrPreflightDenied
	}
	subject, ok := l.Sessions.Current()
	if !ok || subject.Status != pdp.StatusLinked || subject.UserID == "" {
		return BindingContext{}, registeredPlanner{}, ErrPreflightDenied
	}
	caps := append([]string(nil), reg.definition.RequiredCapabilities...)
	return BindingContext{
		InstallationID: identity.ID, BundleVersion: ctx.BundleVersion, BundleDigest: ctx.BundleDigest,
		Subject: subject.UserID, SubjectSource: subject.Source, SubjectExternalID: subject.ExternalID,
		AgentID: agentID, Tool: toolName, Route: ConnectorDispatch{ConnectorID: reg.definition.Route.ConnectorBinding.ConnectorID, RequiredCapabilities: caps},
		ParentSpan: parentSpan, DelegationDepth: depth,
	}, reg, nil
}

func (l *LocalPDP) registeredPlanner(toolName string) (registeredPlanner, bool) {
	if l.preflight == nil {
		return registeredPlanner{}, false
	}
	l.preflight.mu.RLock()
	defer l.preflight.mu.RUnlock()
	reg, ok := l.preflight.planners[toolName]
	return reg, ok
}

func registrationMatchesBinding(definition ToolDefinition, binding BindingContext) bool {
	route, ok := binding.Route.(ConnectorDispatch)
	return ok && definition.Name == binding.Tool && definition.Route != nil && definition.Route.ConnectorBinding != nil && definition.Route.ConnectorBinding.AgentID == binding.AgentID && definition.Route.ConnectorBinding.ConnectorID == route.ConnectorID && equalStrings(definition.RequiredCapabilities, route.RequiredCapabilities)
}

func bundleToolMatchesRegistration(tool policybundle.V2Tool, definition ToolDefinition) bool {
	if definition.Route == nil || definition.Route.ConnectorBinding == nil || tool.Name != definition.Name || tool.Source != definition.Source || tool.Route.ConnectorBinding == nil || tool.Route.ConnectorBinding.ConnectorID != definition.Route.ConnectorBinding.ConnectorID || !equalStrings(tool.RequiredCapabilities, definition.RequiredCapabilities) || len(tool.ResourceTypes) != len(definition.ResourceTypes) {
		return false
	}
	for i, resource := range tool.ResourceTypes {
		if resource.Type != definition.ResourceTypes[i].Type || resource.ParentType != definition.ResourceTypes[i].ParentType {
			return false
		}
	}
	return true
}
