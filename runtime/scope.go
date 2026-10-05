package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type InvokingSubject struct {
	Source   string
	Value    string
	AuthTime time.Time
}

type Scope struct {
	ID              string
	InvokingSubject *InvokingSubject
	ParentScopeID   string
	AgentID         string
	Depth           int
	CreatedAt       time.Time
}

func MintScope(parentScope *Scope, agentID string) *Scope {
	var invokingSubject *InvokingSubject
	if parentScope != nil {
		invokingSubject = parentScope.InvokingSubject
	}

	return &Scope{
		ID:              generateScopeID(),
		InvokingSubject: invokingSubject,
		ParentScopeID:   getParentScopeID(parentScope),
		AgentID:         agentID,
		Depth:           getScopeDepth(parentScope),
		CreatedAt:       time.Now().UTC(),
	}
}

func generateScopeID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "scope_" + hex.EncodeToString(b)
}

func getParentScopeID(parentScope *Scope) string {
	if parentScope == nil {
		return ""
	}
	return parentScope.ID
}

func getScopeDepth(parentScope *Scope) int {
	if parentScope == nil {
		return 0
	}
	return parentScope.Depth + 1
}
