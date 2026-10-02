package connectorruntime

import (
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/policybundlehealth"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func currentPolicyBundleHealth(cfg Config, identity *RuntimeIdentity) *policybundlehealth.Health {
	if identity == nil {
		return nil
	}
	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err != nil {
		return nil
	}
	workspaceID := ""
	if identity.WorkspaceID != nil {
		workspaceID = *identity.WorkspaceID
	}
	health, err := store.HealthReport(identity.ID, identity.OrgID, workspaceID, time.Now().UTC())
	if err != nil {
		return nil
	}
	return health
}
