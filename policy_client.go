package connectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

var (
	ErrPolicyInstallationRevoked = errors.New("runtime installation is revoked or inactive")
	ErrPolicyBundleNotReady      = errors.New("policy bundle is not ready")
)

type policyControlClient struct {
	baseURL, token string
	http           *http.Client
}

func newPolicyControlClient(baseURL, token string, timeout time.Duration) *policyControlClient {
	return &policyControlClient{strings.TrimRight(baseURL, "/"), token, &http.Client{Timeout: timeout}}
}
func (c *policyControlClient) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build runtime policy request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}
func (c *policyControlClient) FetchKeys(ctx context.Context) (policybundle.KeySet, string, error) {
	resp, err := c.request(ctx, http.MethodGet, "/api/v1/runtime/policy-signing-keys", nil)
	if err != nil {
		return policybundle.KeySet{}, "", fmt.Errorf("fetch policy signing keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return policybundle.KeySet{}, "", ErrPolicyInstallationRevoked
	}
	if resp.StatusCode != http.StatusOK {
		return policybundle.KeySet{}, "", fmt.Errorf("policy signing keys returned status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return policybundle.KeySet{}, "", err
	}
	keys, err := policybundle.ParseKeySet(b)
	if err != nil {
		return policybundle.KeySet{}, "", fmt.Errorf("invalid policy signing keys: %w", err)
	}
	keyETag := resp.Header.Get("ETag")
	if keyETag == "" {
		return keys, "", errors.New("policy signing keys response is missing ETag")
	}
	return keys, keyETag, nil
}
func (c *policyControlClient) FetchBundle(ctx context.Context, etag string) (body []byte, gotETag, keysETag string, version int64, unchanged bool, err error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/runtime/policy-bundles/current", nil)
	if e != nil {
		err = e
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", policybundle.PayloadType)
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		err = fmt.Errorf("fetch policy bundle: %w", e)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		err = ErrPolicyInstallationRevoked
		return
	}
	if resp.StatusCode == http.StatusConflict {
		err = ErrPolicyBundleNotReady
		return
	}
	if resp.StatusCode == http.StatusNotModified {
		unchanged = true
		gotETag = resp.Header.Get("ETag")
		keysETag = resp.Header.Get("Kei-Policy-Keys-ETag")
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("policy bundle returned status %d", resp.StatusCode)
		return
	}
	body, e = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if e != nil {
		err = fmt.Errorf("read policy bundle: %w", e)
		return
	}
	gotETag = resp.Header.Get("ETag")
	keysETag = resp.Header.Get("Kei-Policy-Keys-ETag")
	version, _ = strconv.ParseInt(resp.Header.Get("Kei-Policy-Bundle-Version"), 10, 64)
	return
}

type subjectResolveRequest struct {
	PlatformUserID string `json:"platform_user_id,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
}

func (c *policyControlClient) ResolveSubject(ctx context.Context, req subjectResolveRequest) (policybundle.Subject, error) {
	b, _ := json.Marshal(req)
	resp, err := c.request(ctx, http.MethodPost, "/api/v1/runtime/subject-attributes:resolve", b)
	if err != nil {
		return policybundle.Subject{}, fmt.Errorf("resolve subject attributes: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return policybundle.Subject{}, ErrPolicyInstallationRevoked
	}
	if resp.StatusCode != http.StatusOK {
		return policybundle.Subject{}, fmt.Errorf("subject resolution returned status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var subject policybundle.Subject
	if err := decoder.Decode(&subject); err != nil {
		return subject, fmt.Errorf("decode subject attributes: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return subject, errors.New("subject resolution response contains trailing data")
	}
	allowed := map[string]bool{"linked_approved": true, "unlinked": true, "linked_unassigned": true, "linked_unapproved": true, "linked_pending": true, "linked_denied": true, "linked_approved_other_workspace": true}
	if !allowed[subject.Status] || subject.MaxAgeSeconds < 0 || subject.MaxAgeSeconds > 60 {
		return subject, errors.New("subject resolution response is unsupported")
	}
	if subject.Status == "linked_approved" && subject.UserID == "" {
		return subject, errors.New("approved subject response has no user id")
	}
	if subject.Status != "linked_approved" && len(subject.EffectiveGroups) > 0 {
		return subject, errors.New("unapproved subject response included groups")
	}
	return subject, nil
}

// syncPolicyBundle obtains keys only over the authenticated control-plane channel,
// pins revocations, and activates only a strictly newer valid bundle.
func syncPolicyBundle(ctx context.Context, cfg Config, identity *RuntimeIdentity, timeout time.Duration) error {
	if identity == nil || identity.WorkspaceID == nil {
		return errors.New("runtime identity has no workspace audience")
	}
	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err != nil {
		return err
	}
	client := newPolicyControlClient(cfg.RuntimeControlPlaneURL, cfg.RuntimeToken, timeout)
	keys, pinnedKeysETag, err := client.FetchKeys(ctx)
	if errors.Is(err, ErrPolicyInstallationRevoked) {
		_ = store.Revoke(time.Now().UTC())
		return err
	}
	if err != nil {
		_ = store.RefreshFailed(time.Now().UTC())
		return err
	}
	if err := store.PinKeys(keys); err != nil {
		return err
	}
	etag := ""
	if active, _, checkErr := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC(), cfg.IsProduction()); checkErr == nil && active != nil {
		etag = active.Digest
	}
	body, bundleETag, responseKeysETag, headerVersion, unchanged, err := client.FetchBundle(ctx, etag)
	if errors.Is(err, ErrPolicyBundleNotReady) {
		return nil
	}
	if errors.Is(err, ErrPolicyInstallationRevoked) {
		_ = store.Revoke(time.Now().UTC())
		return err
	}
	if err != nil {
		_ = store.RefreshFailed(time.Now().UTC())
		return err
	}
	if responseKeysETag == "" {
		return errors.New("policy bundle response is missing Kei-Policy-Keys-ETag")
	}
	if responseKeysETag != pinnedKeysETag {
		keys, pinnedKeysETag, err = client.FetchKeys(ctx)
		if err != nil {
			return err
		}
		if err := store.PinKeys(keys); err != nil {
			return err
		}
		body, bundleETag, responseKeysETag, headerVersion, unchanged, err = client.FetchBundle(ctx, "")
		if errors.Is(err, ErrPolicyInstallationRevoked) {
			_ = store.Revoke(time.Now().UTC())
			return err
		}
		if err != nil && !errors.Is(err, ErrPolicyBundleNotReady) {
			return err
		}
		if errors.Is(err, ErrPolicyBundleNotReady) {
			return nil
		}
		if responseKeysETag == "" || responseKeysETag != pinnedKeysETag {
			return errors.New("policy signing keys changed during bundle fetch")
		}
	}
	if unchanged {
		if bundleETag != "" && strings.Trim(bundleETag, `"`) != etag {
			return errors.New("unchanged bundle ETag does not match active bundle")
		}
		if _, _, err := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC(), cfg.IsProduction()); err != nil {
			return fmt.Errorf("unchanged response without valid active bundle: %w", err)
		}
		return store.RefreshSucceeded(time.Now().UTC())
	}
	if bundleETag == "" || headerVersion < 1 {
		return errors.New("policy bundle response is missing ETag or version")
	}
	candidate, err := policybundle.Verify(body, store.PinnedKeys(), identity.ID, identity.OrgID, *identity.WorkspaceID, store.HighestVersion(), time.Now().UTC(), cfg.IsProduction())
	if err != nil {
		_ = store.RefreshFailed(time.Now().UTC())
		return fmt.Errorf("policy bundle candidate rejected: %w", err)
	}
	if bundleETag != "" && strings.Trim(bundleETag, `"`) != candidate.Digest {
		_ = store.RefreshFailed(time.Now().UTC())
		return errors.New("catalog ETag does not match signed payload digest")
	}
	if headerVersion > 0 && headerVersion != candidate.Payload.BundleVersion {
		_ = store.RefreshFailed(time.Now().UTC())
		return errors.New("catalog bundle version header does not match signed payload")
	}
	if _, err := store.Activate(body, identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC(), cfg.IsProduction()); err != nil {
		_ = store.RefreshFailed(time.Now().UTC())
		return fmt.Errorf("activate verified policy bundle: %w", err)
	}
	return nil
}
func revokePolicyState(cfg Config) {
	if strings.TrimSpace(cfg.RuntimeStateDir) == "" {
		return
	}
	store, err := policybundle.OpenStore(cfg.RuntimeStateDir)
	if err == nil {
		_ = store.Revoke(time.Now().UTC())
	}
}
func isRuntimeRevocation(err error) bool {
	var who *WhoamiFailure
	if errors.As(err, &who) && who.Category == WhoamiFailureHTTPStatus && (who.StatusCode == http.StatusUnauthorized || who.StatusCode == http.StatusForbidden) {
		return true
	}
	var beat *HeartbeatFailure
	return errors.As(err, &beat) && beat.Outcome == HeartbeatUnauthorized
}
