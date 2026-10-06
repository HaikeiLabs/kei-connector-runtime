package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

var (
	ErrPolicyInstallationRevoked = errors.New("runtime installation is revoked or inactive")
	ErrPolicyAuthorizationDenied = errors.New("runtime policy endpoint denied authorization")
	ErrPolicyBundleNotReady      = errors.New("policy bundle is not ready")
)

type policyControlClient struct {
	baseURL, token    string
	http              *http.Client
	allowLoopbackHTTP bool
}

func NewPolicyControlClient(baseURL, token string, timeout time.Duration, allowLoopbackHTTP bool) *policyControlClient {
	return &policyControlClient{strings.TrimRight(baseURL, "/"), token, &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, allowLoopbackHTTP}
}

func ValidatePolicyControlPlaneURL(raw string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return errors.New("invalid runtime control-plane URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("runtime control-plane URL has no host")
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("runtime control-plane URL has invalid port")
		}
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme == "http" && loopback && allowLoopbackHTTP {
		return nil
	}
	return errors.New("runtime control-plane URL must use HTTPS")
}

func ValidateRuntimeTokenFormat(token string) error {
	if token == "" {
		return errors.New("KEI_RUNTIME_TOKEN must not be empty")
	}
	if !strings.HasPrefix(token, "kh_live_") {
		return errors.New("KEI_RUNTIME_TOKEN must start with kh_live_")
	}
	if len(token) < 20 {
		return errors.New("KEI_RUNTIME_TOKEN is too short")
	}
	return nil
}

func (c *policyControlClient) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	if err := ValidateRuntimeTokenFormat(c.token); err != nil {
		return nil, err
	}
	if err := ValidatePolicyControlPlaneURL(c.baseURL, c.allowLoopbackHTTP); err != nil {
		return nil, err
	}
	return http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
}

func (c *policyControlClient) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return nil, fmt.Errorf("build runtime policy request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *policyControlClient) FetchBundle(ctx context.Context, etag string) (body []byte, gotETag, contentType string, version int64, unchanged bool, err error) {
	req, e := c.newRequest(ctx, http.MethodGet, "/api/v1/runtime/policy-bundles/current", nil)
	if e != nil {
		err = e
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", policybundle.ContentType)
	req.Header.Set("Accept-Encoding", "identity")
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	resp, e := c.http.Do(req)
	if e != nil {
		err = fmt.Errorf("fetch policy bundle: %w", e)
		return
	}
	defer resp.Body.Close()
	version, _ = strconv.ParseInt(resp.Header.Get("Kei-Policy-Bundle-Version"), 10, 64)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		err = fmt.Errorf("%w: bundle endpoint returned HTTP %d", ErrPolicyAuthorizationDenied, resp.StatusCode)
		return
	}
	if resp.StatusCode == http.StatusConflict {
		err = ErrPolicyBundleNotReady
		return
	}
	if resp.StatusCode == http.StatusNotModified {
		unchanged = true
		gotETag = resp.Header.Get("ETag")
		contentType = resp.Header.Get("Content-Type")
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("policy bundle returned status %d", resp.StatusCode)
		return
	}
	if encoding := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding"))); encoding != "" && encoding != "identity" {
		err = errors.New("policy bundle response uses unsupported content encoding")
		return
	}
	body, e = io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if e != nil {
		err = fmt.Errorf("read policy bundle: %w", e)
		return
	}
	if len(body) > 8<<20 {
		body = nil
		err = errors.New("policy bundle exceeds 8 MiB limit")
		return
	}
	gotETag = resp.Header.Get("ETag")
	contentType = resp.Header.Get("Content-Type")
	return
}

type SubjectResolveRequest struct {
	PlatformUserID string `json:"platform_user_id,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
}

type SubjectResolutionFailure struct {
	Category       string
	HTTPStatus     int
	TransportPhase string
	TransportKind  string
}

// classifySubjectResolutionTransportError returns a bounded diagnostic label;
// it deliberately does not expose raw network errors, URLs, or credentials.
func classifySubjectResolutionTransportError(err error) string {
	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return "tls"
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "tls"
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return "tls"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return "network"
	}
	return "request_setup_or_network"
}

func (e *SubjectResolutionFailure) Error() string { return "subject resolution failed" }

func (c *policyControlClient) ResolveSubject(ctx context.Context, req SubjectResolveRequest) (policybundle.Subject, error) {
	b, _ := json.Marshal(req)
	path := "/api/v1/runtime/subject-attributes:resolve"
	httpReq, err := c.newRequest(ctx, http.MethodPost, path, b)
	if err != nil {
		return policybundle.Subject{}, &SubjectResolutionFailure{
			Category:       "transport",
			TransportPhase: "request_build",
			TransportKind:  "request_setup",
		}
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return policybundle.Subject{}, &SubjectResolutionFailure{
			Category:       "transport",
			TransportPhase: "http_client_do",
			TransportKind:  classifySubjectResolutionTransportError(err),
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return policybundle.Subject{}, fmt.Errorf("%w: %w", ErrPolicyAuthorizationDenied, &SubjectResolutionFailure{Category: "http_status", HTTPStatus: resp.StatusCode})
	}
	if resp.StatusCode != http.StatusOK {
		return policybundle.Subject{}, &SubjectResolutionFailure{Category: "http_status", HTTPStatus: resp.StatusCode}
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var subject policybundle.Subject
	if err := decoder.Decode(&subject); err != nil {
		return subject, &SubjectResolutionFailure{Category: "decode"}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return subject, &SubjectResolutionFailure{Category: "decode"}
	}
	allowed := map[string]bool{"linked_approved": true, "unlinked": true, "linked_unassigned": true, "linked_unapproved": true, "linked_pending": true, "linked_denied": true, "linked_approved_other_workspace": true}
	if !allowed[subject.Status] || subject.MaxAgeSeconds < 0 || subject.MaxAgeSeconds > 60 {
		return subject, &SubjectResolutionFailure{Category: "invalid_response"}
	}
	if subject.Status == "linked_approved" && subject.UserID == "" {
		return subject, &SubjectResolutionFailure{Category: "invalid_response"}
	}
	if subject.Status != "linked_approved" && len(subject.EffectiveGroups) > 0 {
		return subject, &SubjectResolutionFailure{Category: "invalid_response"}
	}
	return subject, nil
}

// SyncPolicyBundle fetches an unsigned canonical bundle only over a validated
// HTTPS control-plane channel authenticated by the installation runtime token.
func SyncPolicyBundle(ctx context.Context, cfg PolicyConfig, identity *Identity, timeout time.Duration) error {
	if identity == nil || identity.WorkspaceID == nil {
		return errors.New("runtime identity has no workspace audience")
	}
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err != nil {
		return err
	}
	client := NewPolicyControlClient(cfg.ControlPlaneURL(), cfg.Token(), timeout, !cfg.IsProduction())
	etag := ""
	if active, _, checkErr := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC()); checkErr == nil && active != nil {
		etag = active.Digest
	}
	body, bundleETag, contentType, headerVersion, unchanged, err := client.FetchBundle(ctx, etag)
	if errors.Is(err, ErrPolicyBundleNotReady) {
		return store.RefreshFailed(time.Now().UTC())
	}
	if errors.Is(err, ErrPolicyInstallationRevoked) {
		_ = store.Revoke(time.Now().UTC())
		return err
	}
	if errors.Is(err, ErrPolicyAuthorizationDenied) {
		_ = store.RefreshFailed(time.Now().UTC())
		return err
	}
	if err != nil {
		_ = store.RefreshFailed(time.Now().UTC())
		return err
	}
	if unchanged {
		if bundleETag != `"`+etag+`"` {
			return errors.New("unchanged bundle ETag does not match active bundle")
		}
		active, _, checkErr := store.Check(identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC())
		if checkErr != nil {
			return fmt.Errorf("unchanged response without valid active bundle: %w", checkErr)
		}
		if headerVersion < 1 || headerVersion != active.Payload.BundleVersion {
			return errors.New("unchanged bundle version header does not match active bundle")
		}
		return store.RefreshSucceeded(time.Now().UTC())
	}
	now := time.Now().UTC()
	reject := func(cause error) error { _ = store.RecordRejectedCandidate(now, cause); return cause }
	if bundleETag == "" || headerVersion < 1 {
		return reject(errors.New("policy bundle response is missing ETag or version"))
	}
	mediaType, mediaParams, mediaErr := mime.ParseMediaType(contentType)
	if mediaErr != nil || mediaType != policybundle.ContentType || len(mediaParams) != 0 {
		return reject(errors.New("policy bundle response has an invalid content type"))
	}
	bodyDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	if bundleETag != `"`+bodyDigest+`"` {
		return reject(errors.New("catalog ETag does not match policy bundle digest"))
	}
	candidate, err := policybundle.Validate(body, identity.ID, identity.OrgID, *identity.WorkspaceID, store.HighestVersionFor(identity.ID, identity.OrgID, *identity.WorkspaceID), now)
	if err != nil {
		_ = store.RecordRejectedCandidate(now, err)
		return fmt.Errorf("policy bundle candidate rejected: %w", err)
	}
	if candidate.Digest != bodyDigest {
		return reject(errors.New("validated policy bundle digest differs from response digest"))
	}
	if headerVersion != candidate.Payload.BundleVersion {
		return reject(errors.New("catalog bundle version header does not match policy bundle"))
	}
	if _, err := store.Activate(body, identity.ID, identity.OrgID, *identity.WorkspaceID, time.Now().UTC()); err != nil {
		_ = store.RefreshFailed(time.Now().UTC())
		return fmt.Errorf("activate validated policy bundle: %w", err)
	}
	return nil
}

func RevokePolicyState(cfg PolicyConfig) {
	if strings.TrimSpace(cfg.PolicyStateDir()) == "" {
		return
	}
	store, err := policybundle.OpenStore(cfg.PolicyStateDir())
	if err == nil {
		_ = store.Revoke(time.Now().UTC())
	}
}
