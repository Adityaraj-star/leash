package control

import (
	"crypto/subtle"
	"sort"
	"time"

	"github.com/Adityaraj-star/leash/internal/money"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

// MerchantOrder is what a merchant may see about a payment Leash is holding for it:
// enough to ship the goods, and nothing about the mandate, the user or the policy
// decision behind it.
type MerchantOrder struct {
	RequestID string       `json:"request_id"`
	Items     []string     `json:"items"`
	Amount    money.Amount `json:"amount"`
	CreatedAt time.Time    `json:"created_at"`
}

// MerchantOrders lists the orders held in escrow for one merchant that are waiting
// to be shipped. The merchant proves who it is with its delivery secret, the same
// secret AttestDelivery checks; a wrong id or secret gets ErrUnauthorized.
func (p *Plane) MerchantOrders(merchantID, secret string) ([]MerchantOrder, error) {
	mer, ok := p.cfg.Registry.Lookup(merchantID)
	if !ok || mer.DeliverySecret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(mer.DeliverySecret)) != 1 {
		return nil, ErrUnauthorized
	}
	out := []MerchantOrder{}
	for _, r := range p.eng.List() {
		if r.MerchantID != merchantID || r.State != settlement.Authorized {
			continue
		}
		out = append(out, MerchantOrder{RequestID: r.ID, Items: r.Items, Amount: r.Amount, CreatedAt: r.CreatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
