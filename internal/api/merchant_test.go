package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Adityaraj-star/leash/internal/control"
	"github.com/Adityaraj-star/leash/internal/mandate"
	"github.com/Adityaraj-star/leash/internal/settlement"
)

func (r *rig) deliver(secret, body string) (int, []byte) {
	r.t.Helper()
	req, _ := http.NewRequest("POST", r.srv.URL+"/merchant/delivery", strings.NewReader(body))
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, []byte(buf.String())
}

func deliveryBody(id string, delivered bool) string {
	return fmt.Sprintf(`{"merchant_id":"legitgifts","request_id":%q,"delivered":%v,"reference":"TRK-1"}`, id, delivered)
}

// authorizedRequest takes a request through step-up and a signed approval.
func authorizedRequest(r *rig, key string) string {
	id := r.strictStepUp(key)
	var am struct{ Message string }
	json.Unmarshal(r.must("GET", "/api/requests/"+id+"/approval", "", 200), &am)
	sig, _ := mandate.Sign(r.priv, []byte(am.Message))
	var out control.Outcome
	json.Unmarshal(r.must("POST", "/api/requests/"+id+"/approve", fmt.Sprintf(`{"signature":%q}`, base64.StdEncoding.EncodeToString(sig)), 200), &out)
	if out.State != settlement.Authorized {
		r.t.Fatalf("setup: %+v", out)
	}
	return id
}

func TestAMerchantConfirmsDeliveryAndIsPaid(t *testing.T) {
	r, _, _ := strictRig(t)
	r.enrollAndRegister()
	id := authorizedRequest(r, "k1")

	code, b := r.deliver("s3cret", deliveryBody(id, true))
	var out control.Outcome
	json.Unmarshal(b, &out)
	if code != http.StatusOK || out.State != settlement.PaidOut {
		t.Fatalf("delivery = %d %s", code, b)
	}
	// Confirming twice is a conflict, not a second payout.
	if code, _ := r.deliver("s3cret", deliveryBody(id, true)); code != http.StatusConflict {
		t.Fatalf("a second confirmation = %d, want 409", code)
	}
}

func TestANegativeDeliveryReleasesTheHold(t *testing.T) {
	r, _, _ := strictRig(t)
	r.enrollAndRegister()
	id := authorizedRequest(r, "k1")
	code, b := r.deliver("s3cret", deliveryBody(id, false))
	var out control.Outcome
	json.Unmarshal(b, &out)
	if code != http.StatusOK || out.State != settlement.Voided {
		t.Fatalf("a failed delivery must release the hold: %d %s", code, b)
	}
}

func TestOnlyTheMerchantsOwnSecretWorks(t *testing.T) {
	r, _, _ := strictRig(t)
	r.enrollAndRegister()
	id := authorizedRequest(r, "k1")
	for name, secret := range map[string]string{
		"no secret":              "",
		"wrong secret":           "nope-nope-nope",
		"the operator token":     token,
		"a prefix of the secret": "s3cr",
	} {
		if code, _ := r.deliver(secret, deliveryBody(id, true)); code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, code)
		}
	}
	// Another merchant id with this merchant's secret, and an unknown request id.
	if code, _ := r.deliver("s3cret", strings.Replace(deliveryBody(id, true), "legitgifts", "someoneelse", 1)); code != http.StatusForbidden {
		t.Errorf("wrong merchant id = %d", code)
	}
	if code, _ := r.deliver("s3cret", deliveryBody("req_nope", true)); code != http.StatusForbidden {
		t.Errorf("unknown request = %d (it must look the same as a wrong secret)", code)
	}
	if st := r.stateOf(id); st != settlement.Authorized {
		t.Fatalf("nothing may change after refused attempts: %s", st)
	}
	// The merchant's secret opens nothing else.
	req, _ := http.NewRequest("GET", r.srv.URL+"/api/state", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the merchant secret must not open the operator API: %d", resp.StatusCode)
	}
}

func (r *rig) stateOf(id string) settlement.State {
	var req settlement.Request
	json.Unmarshal(r.must("GET", "/api/requests/"+id, "", 200), &req)
	return req.State
}

func TestGuessingMerchantSecretsIsRateLimited(t *testing.T) {
	r, _, clk := strictRig(t)
	r.enrollAndRegister()
	id := authorizedRequest(r, "k1")
	for i := 0; i < maxDeliveryFailures; i++ {
		if code, _ := r.deliver(fmt.Sprintf("guess-%d", i), deliveryBody(id, true)); code != http.StatusForbidden {
			t.Fatalf("attempt %d = %d", i, code)
		}
	}
	// Further attempts are refused outright, even with the right secret.
	if code, _ := r.deliver("s3cret", deliveryBody(id, true)); code != http.StatusTooManyRequests {
		t.Fatalf("after too many failures = %d, want 429", code)
	}
	// Another merchant id is not affected, and the window passes.
	clk.add(2 * time.Minute)
	if code, _ := r.deliver("s3cret", deliveryBody(id, true)); code != http.StatusOK {
		t.Fatalf("after the window = %d, want 200", code)
	}
}

func TestDeliveryBodyIsValidated(t *testing.T) {
	r, _, _ := strictRig(t)
	for _, body := range []string{`{}`, `{"merchant_id":"legitgifts"}`, `{"merchant_id":"legitgifts","request_id":"req_x"}`, `not json`,
		`{"merchant_id":"legitgifts","request_id":"req_x","delivered":true,"extra":1}`} {
		if code, _ := r.deliver("s3cret", body); code != http.StatusBadRequest {
			t.Errorf("%q = %d, want 400", body, code)
		}
	}
}
