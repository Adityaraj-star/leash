package control

import (
	"context"
	"errors"
	"sync"

	"github.com/Adityaraj-star/leash/internal/ledger"
	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

// The control plane has five kinds of caller. Which one you are decides what you
// can reach, and the types below make that a compile-time fact: the MCP handlers
// receive an AgentAPI and have no way to call anything else.
//
//	AgentAPI     the AI agent (via MCP): browse, ask for payment, read status, release a hold
//	UserAPI      the human principal (dashboard): enroll, mandates, approvals, revoke, refund
//	MerchantAPI  a merchant attesting delivery with its shared secret
//	WebhookAPI   PayPal webhooks, after paypal.Client.VerifyWebhook has checked the signature
//	OperatorAPI  the server's own maintenance loop
//
// The agent is the one caller that may be hostile (a poisoned page can steer it),
// so AgentAPI is deliberately small and cannot name its own session: a session is
// bound to the connection by OpenAgentConn, and the agent can neither choose nor
// switch it.

// AgentAPI is everything an AI agent may call.
type AgentAPI interface {
	SessionID() string
	Browse(ctx context.Context, rawURL string) (BrowseResult, error)
	RequestPayment(ctx context.Context, req PaymentRequest) (Outcome, error)
	Status(id string) (Outcome, error)
	ReportProblem(ctx context.Context, id, reason string) (Outcome, error)
}

// UserAPI is what the human principal may call.
type UserAPI interface {
	EnrollWithSecret(pub []byte, secret string) (string, error)
	RegisterMandate(raw, sig []byte) (*mandate.Mandate, error)
	Revoke(ctx context.Context, mandateID, by string) ([]string, error)
	SetUserMessage(session, text string) error
	ApproveStepUpSigned(ctx context.Context, id string, sig []byte) (Outcome, error)
	RejectStepUp(id, by string) (Outcome, error)
	RetryAuthorize(ctx context.Context, id string) (Outcome, error)
	UserRefund(ctx context.Context, id, by, reason string) (Outcome, error)
	UserDispute(id, by, reason string) (Outcome, error)
	Mandates() []MandateView
	Requests() []*settlement.Request
	Request(id string) (*settlement.Request, error)
	Subscribe() (<-chan ledger.Entry, func())
}

// MerchantAPI is what a merchant may call.
type MerchantAPI interface {
	AttestDelivery(ctx context.Context, merchantID, secret, requestID string, d settlement.Delivery) (Outcome, error)
}

// WebhookAPI is for PayPal webhooks. Verify the signature first.
type WebhookAPI interface {
	OnCaptureCompleted(ctx context.Context, requestID, captureID string) (Outcome, error)
	OnCaptureDenied(requestID, captureID, reason string) (Outcome, error)
	OnPayoutUpdate(ctx context.Context, requestID string) (Outcome, error)
}

// OperatorAPI is the server's own maintenance entry points.
type OperatorAPI interface {
	Sweep(ctx context.Context) ([]string, error)
	Reconcile(ctx context.Context) ([]string, error)
	RetrySettle(ctx context.Context, id string) (Outcome, error)
}

var (
	_ AgentAPI    = (*AgentConn)(nil)
	_ UserAPI     = (*Plane)(nil)
	_ MerchantAPI = (*Plane)(nil)
	_ WebhookAPI  = (*Plane)(nil)
	_ OperatorAPI = (*Plane)(nil)
)

// ErrNotYours means the request was not created through this agent connection.
var ErrNotYours = errors.New("control: that request does not belong to this agent connection")

// AgentConn is one agent's connection to Leash. It is bound to a server-issued
// session: every page the agent reads and every payment it asks for is judged
// under that one session, and the agent cannot choose another. It can only read or
// release requests it created itself.
type AgentConn struct {
	plane   *Plane
	session string

	mu      sync.Mutex
	created map[string]bool
}

// OpenAgentConn is called by the SERVER when an agent connects (an MCP session, an
// API token), never on the agent's say-so. Give each agent connection its own.
func (p *Plane) OpenAgentConn() *AgentConn {
	return &AgentConn{plane: p, session: p.NewSession(), created: map[string]bool{}}
}

// SessionID is the connection's session. The USER side needs it to attach the
// user's own words (SetUserMessage); the agent has no use for it.
func (c *AgentConn) SessionID() string { return c.session }

// Browse fetches a page under this connection's session.
func (c *AgentConn) Browse(ctx context.Context, rawURL string) (BrowseResult, error) {
	return c.plane.Browse(ctx, c.session, rawURL)
}

// RequestPayment asks for a payment. Whatever Session the caller put in req is
// overwritten with the connection's own.
func (c *AgentConn) RequestPayment(ctx context.Context, req PaymentRequest) (Outcome, error) {
	req.Session = c.session
	o, err := c.plane.RequestPayment(ctx, req)
	if o.RequestID != "" {
		c.mu.Lock()
		c.created[o.RequestID] = true
		c.mu.Unlock()
	}
	return o, err
}

func (c *AgentConn) owns(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.created[id]
}

// Status reports a request created through this connection.
func (c *AgentConn) Status(id string) (Outcome, error) {
	if !c.owns(id) {
		return Outcome{}, ErrNotYours
	}
	return c.plane.Status(id)
}

// ReportProblem releases a request created through this connection (see
// Plane.ReportProblem: it can never move money that was already taken).
func (c *AgentConn) ReportProblem(ctx context.Context, id, reason string) (Outcome, error) {
	if !c.owns(id) {
		return Outcome{}, ErrNotYours
	}
	return c.plane.ReportProblem(ctx, id, reason)
}
