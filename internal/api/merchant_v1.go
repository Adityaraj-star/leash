package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

// The merchant's back-office API. A merchant says who it is with an X-Merchant-Id
// header and proves it with its delivery secret as a bearer token:
//
//	GET  /merchant/v1/orders                      orders held for this merchant, waiting to ship
//	POST /merchant/v1/orders/{id}/delivery        {"delivered":true,"reference":"TRK-1","note":"..."}
//
// Every authentication failure is the same 401, whether the id, the secret or the
// order was wrong, so the endpoint does not tell a guesser which part was right.
// Wrong attempts are counted per merchant id with the same limiter as
// POST /merchant/delivery, and a throttled merchant gets 429 even with the right secret.

// merchantCaller returns the merchant id and secret from the request, and false
// (after answering) when the caller is currently throttled.
func (s *Server) merchantCaller(w http.ResponseWriter, r *http.Request) (id, secret string, ok bool) {
	id = r.Header.Get("X-Merchant-Id")
	if len(id) > 64 {
		id = id[:64]
	}
	if s.deliveryBlocked(id) {
		w.Header().Set("Retry-After", strconv.Itoa(int(deliveryFailWindow.Seconds())))
		writeErr(w, http.StatusTooManyRequests, "too many wrong secrets; try again in a minute")
		return "", "", false
	}
	return id, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), true
}

func (s *Server) merchantOrders(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := s.merchantCaller(w, r)
	if !ok {
		return
	}
	orders, err := s.Plane.MerchantOrders(id, secret)
	if errors.Is(err, control.ErrUnauthorized) {
		s.deliveryFailed(id)
		writeErr(w, http.StatusUnauthorized, "not authorized")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, orders)
}

func (s *Server) merchantOrderDelivery(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := s.merchantCaller(w, r)
	if !ok {
		return
	}
	var in struct {
		Delivered *bool  `json:"delivered"`
		Reference string `json:"reference"`
		Note      string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Delivered == nil {
		writeErr(w, http.StatusBadRequest, "delivered is required")
		return
	}
	out, err := s.Plane.AttestDelivery(r.Context(), id, secret, r.PathValue("id"), settlement.Delivery{
		Delivered: *in.Delivered, Reference: in.Reference, Note: in.Note,
	})
	switch {
	case errors.Is(err, control.ErrUnauthorized):
		s.deliveryFailed(id)
		writeErr(w, http.StatusUnauthorized, "not authorized")
	case err != nil && out.RequestID != "":
		// Recorded, but a later step failed (for example the payout). The funds are
		// safe and the maintenance pass retries.
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "outcome": out})
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, http.StatusOK, out)
	}
}
