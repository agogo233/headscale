package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// seedAuthRequest stores a pending registration auth cache entry under authID so
// an AuthRegister/Approve/Reject call has a real session to act on. Capturing
// the keys/authID at the call site keeps isolated apps identical.
func seedAuthRequest(
	user string,
	authID types.AuthID,
	machineKey key.MachinePublic,
	nodeKey key.NodePublic,
	discoKey key.DiscoPublic,
	hostname string,
) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		app.state.CreateUserForTest(user)

		regData := &types.RegistrationData{
			MachineKey: machineKey,
			NodeKey:    nodeKey,
			DiscoKey:   discoKey,
			Hostname:   hostname,
			Hostinfo:   &tailcfg.Hostinfo{Hostname: hostname},
		}

		app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))
	}
}

func TestAPIV1AuthRegister(t *testing.T) {
	t.Run("happy path parity", func(t *testing.T) {
		// Capture keys/authID once so both isolated apps register the identical
		// node and produce byte-equal bodies.
		authID := types.MustAuthID()
		machineKey := key.NewMachine().Public()
		nodeKey := key.NewNode().Public()
		discoKey := key.NewDisco().Public()

		seed := seedAuthRequest("alice", authID, machineKey, nodeKey, discoKey, "regnode")
		body := fmt.Appendf(nil, `{"user":"alice","authId":%q}`, authID.String())

		assertParityIsolated(t, seed, http.MethodPost, "/api/v1/auth/register", body)
	})

	t.Run("happy path response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		seedAuthRequest(
			"alice", authID,
			key.NewMachine().Public(),
			key.NewNode().Public(),
			key.NewDisco().Public(),
			"regnode",
		)(t, h.app)

		body := fmt.Appendf(nil, `{"user":"alice","authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/register", body)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		assert.Equal(t, "REGISTER_METHOD_CLI", got.Node["registerMethod"])
		// EmitUnpopulated parity: an unset expiry (we passed none) is null, an
		// unset embedded pre-auth key is null, and repeated fields are []
		// rather than omitted.
		assert.Contains(t, got.Node, "expiry")
		assert.Nil(t, got.Node["expiry"])
		assert.Contains(t, got.Node, "preAuthKey")
		assert.Nil(t, got.Node["preAuthKey"])
		assert.Equal(t, []any{}, got.Node["subnetRoutes"])
		assert.NotNil(t, got.Node["user"])
	})

	// A malformed auth_id is bad input (400), matching AuthApprove/AuthReject.
	t.Run("invalid auth_id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice")(t, h.app)
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/register",
			[]byte(`{"user":"alice","authId":"not-a-valid-auth-id"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := fmt.Appendf(nil, `{"user":"ghost","authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/register", body)
		assertStatus(t, res, http.StatusNotFound)
	})

	// Valid auth_id but no cached session: HandleNodeFromAuthPath returns
	// ErrNodeNotFoundRegistrationCache, which maps to 404.
	t.Run("no pending session parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice")(t, h.app)

		body := fmt.Appendf(nil, `{"user":"alice","authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/register", body)
		assertStatus(t, res, http.StatusNotFound)
	})

	// Numeric user values resolve by id, matching the CLI's --user flags.
	t.Run("numeric user resolves by id", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		seedAuthRequest("alice", authID,
			key.NewMachine().Public(), key.NewNode().Public(), key.NewDisco().Public(),
			"regnode",
		)(t, h.app)

		body := fmt.Appendf(nil, `{"user":"1","authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/register", body)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node struct {
				User struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		assert.Equal(t, "1", got.Node.User.ID)
	})
}

func TestAPIV1AuthApprove(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		authReq := types.NewAuthRequest()
		h.app.state.SetAuthCacheEntry(authID, authReq)

		body := fmt.Appendf(nil, `{"authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/approve", body)

		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{}`, string(res.body))

		verdict := <-authReq.WaitForAuth()
		assert.True(t, verdict.Accept(), "approve must finish the session with a passing verdict")
	})

	// Malformed auth_id: AuthApprove returns codes.InvalidArgument → 400.
	t.Run("invalid auth_id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/approve",
			[]byte(`{"authId":"not-a-valid-auth-id"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	// Well-formed auth_id with no pending session: codes.NotFound → 404.
	t.Run("no pending session parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := fmt.Appendf(nil, `{"authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/approve", body)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1AuthReject(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		authReq := types.NewAuthRequest()
		h.app.state.SetAuthCacheEntry(authID, authReq)

		body := fmt.Appendf(nil, `{"authId":%q}`, authID.String())
		res := h.callHuma(http.MethodPost, "/api/v1/auth/reject", body)

		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{}`, string(res.body))

		verdict := <-authReq.WaitForAuth()
		assert.False(t, verdict.Accept(), "reject must finish the session with a failing verdict")
	})

	t.Run("invalid auth_id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/reject",
			[]byte(`{"authId":"not-a-valid-auth-id"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("no pending session parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := fmt.Appendf(nil, `{"authId":%q}`, types.MustAuthID().String())
		res := h.assertParity(t, http.MethodPost, "/api/v1/auth/reject", body)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1AuthListPending(t *testing.T) {
	t.Run("empty cache", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.callHuma(http.MethodGet, "/api/v1/auth/pending", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"authRequests":[]}`, string(res.body))
	})

	t.Run("open registration requests", func(t *testing.T) {
		h := newAPIV1Harness(t)

		authID := types.MustAuthID()
		// seedAuthRequest creates the user (id 1) and the cached request.
		seedAuthRequest("alice", authID,
			key.NewMachine().Public(), key.NewNode().Public(), key.NewDisco().Public(),
			"pending-node",
		)(t, h.app)

		// Attach the resolved OIDC identity so the list item carries a user.
		req, ok := h.app.state.GetAuthCacheEntry(authID)
		require.True(t, ok)
		req.SetPendingConfirmation(&types.PendingRegistrationConfirmation{UserID: 1})
		req.RegistrationData().Hostinfo = &tailcfg.Hostinfo{
			OS:          "linux",
			OSVersion:   "6.1.0",
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		}

		res := h.callHuma(http.MethodGet, "/api/v1/auth/pending", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			AuthRequests []struct {
				AuthID      string   `json:"authId"`
				Hostname    string   `json:"hostname"`
				User        string   `json:"user"`
				OS          string   `json:"os"`
				OSVersion   string   `json:"osVersion"`
				RoutableIPs []string `json:"routableIPs"`
				CreatedAt   string   `json:"createdAt"`
			} `json:"authRequests"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		require.Len(t, got.AuthRequests, 1)

		item := got.AuthRequests[0]
		assert.Equal(t, authID.String(), item.AuthID)
		assert.Equal(t, "pending-node", item.Hostname)
		assert.Equal(t, "alice", item.User)
		assert.Equal(t, "linux", item.OS)
		assert.Equal(t, "6.1.0", item.OSVersion)
		assert.Equal(t, []string{"192.168.1.0/24"}, item.RoutableIPs)
		assert.NotEmpty(t, item.CreatedAt)
	})

	t.Run("finished and non-registration requests are excluded", func(t *testing.T) {
		h := newAPIV1Harness(t)

		open := types.MustAuthID()
		seedAuthRequest("alice", open,
			key.NewMachine().Public(), key.NewNode().Public(), key.NewDisco().Public(),
			"open-node",
		)(t, h.app)

		done := types.MustAuthID()
		doneReq := types.NewRegisterAuthRequest(
			&types.RegistrationData{Hostname: "done-node"},
		)
		h.app.state.SetAuthCacheEntry(done, doneReq)
		doneReq.FinishAuth(types.AuthVerdict{})

		h.app.state.SetAuthCacheEntry(
			types.MustAuthID(),
			types.NewSSHCheckAuthRequest(1, 2),
		)

		res := h.callHuma(http.MethodGet, "/api/v1/auth/pending", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			AuthRequests []struct {
				AuthID   string `json:"authId"`
				Hostname string `json:"hostname"`
			} `json:"authRequests"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		require.Len(t, got.AuthRequests, 1)
		assert.Equal(t, open.String(), got.AuthRequests[0].AuthID)
		assert.Equal(t, "open-node", got.AuthRequests[0].Hostname)
	})
}
