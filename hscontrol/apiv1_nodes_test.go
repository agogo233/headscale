package hscontrol

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// nodeSeed carries fixed key material so isolated apps in a mutation parity test
// register byte-identical nodes; otherwise random keys would defeat body
// comparison.
type nodeSeed struct {
	user       string
	machineKey key.MachinePrivate
	nodeKey    key.NodePrivate
	hostname   string
	tags       []string
}

func newNodeSeed(user, hostname string, tags ...string) nodeSeed {
	return nodeSeed{
		user:       user,
		machineKey: key.NewMachine(),
		nodeKey:    key.NewNode(),
		hostname:   hostname,
		tags:       tags,
	}
}

// register inserts the user, a matching pre-auth key, and the node itself using
// the seed's fixed keys, returning the created node ID.
func (s nodeSeed) register(t *testing.T, app *Headscale) types.NodeID {
	t.Helper()

	user := app.state.CreateUserForTest(s.user)

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, s.tags)
	require.NoError(t, err)

	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  s.nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: s.hostname},
	}

	_, err = app.handleRegisterWithAuthKey(req, s.machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(s.nodeKey.Public())
	require.True(t, found)

	return node.ID()
}

func seedNodes(seeds ...nodeSeed) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		for _, s := range seeds {
			s.register(t, app)
		}
	}
}

func TestAPIV1NodeGet(t *testing.T) {
	t.Run("happy parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node/1", nil)
	})

	t.Run("tagged node parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		// No tagOwners means policy won't authorise a tag, so register via the
		// pre-auth key path, which forces tags regardless of policy.
		seedNodes(newNodeSeed("bob", "node-b", "tag:initial"))(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node/1", nil)
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodGet, "/api/v1/node/99999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodGet, "/api/v1/node/abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("carol", "node-c"))(t, h.app)

		res := h.callHuma(http.MethodGet, "/api/v1/node/1", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		assert.Equal(t, "node-c", got.Node["name"])
		assert.Equal(t, "REGISTER_METHOD_AUTH_KEY", got.Node["registerMethod"])
		// EmitUnpopulated parity: slices present as [], expiry as null.
		assert.Equal(t, []any{}, got.Node["ipAddresses"])
		assert.Equal(t, []any{}, got.Node["tags"])
		assert.Nil(t, got.Node["expiry"])
		assert.Contains(t, got.Node, "user")
		assert.Contains(t, got.Node, "preAuthKey")
		assert.Contains(t, got.Node, "createdAt")
	})
}

func TestAPIV1NodeList(t *testing.T) {
	t.Run("empty returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodGet, "/api/v1/node", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"nodes":[]}`, string(res.body))
	})

	t.Run("empty parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.assertParity(t, http.MethodGet, "/api/v1/node", nil)
	})

	t.Run("all parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node", nil)
	})

	t.Run("filter by user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/node?user=alice", nil)
	})

	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		res := h.assertParity(t, http.MethodGet, "/api/v1/node?user=nope", nil)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1NodeDelete(t *testing.T) {
	t.Run("happy parity", func(t *testing.T) {
		assertParityIsolated(t, seedNodes(newNodeSeed("alice", "node-a")),
			http.MethodDelete, "/api/v1/node/1", nil)
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/node/99999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/node/abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeExpire(t *testing.T) {
	// The embedded pre-auth key's masked prefix is random per app, so isolated
	// body comparison is impossible. GetNode/ListNodes prove full serialisation;
	// here we just assert the mutation took effect.
	t.Run("huma expires node", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/expire", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		// Expiry was nil before; expiring sets it to a concrete timestamp.
		assert.NotNil(t, got.Node["expiry"])
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/expire", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/expire", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeRename(t *testing.T) {
	t.Run("huma renames node", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/rename/renamed-node", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "renamed-node", got.Node["givenName"])
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/rename/whatever", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/rename/whatever", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeSetTags(t *testing.T) {
	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/tags",
			[]byte(`{"tags":["tag:foo"]}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("empty tags parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/1/tags", []byte(`{"tags":[]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("unauthorized tag parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		// No tagOwners in policy → SetNodeTags rejects with InvalidArgument (400).
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/1/tags",
			[]byte(`{"tags":["tag:server"]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/tags",
			[]byte(`{"tags":["tag:foo"]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeSetApprovedRoutes(t *testing.T) {
	t.Run("huma sets approved routes", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/node/1/approve_routes",
			[]byte(`{"routes":[]}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.Node["id"])
		// SubnetRoutes is recomputed from primary routes; empty here but present.
		assert.Equal(t, []any{}, got.Node["approvedRoutes"])
		assert.Equal(t, []any{}, got.Node["subnetRoutes"])
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/99999/approve_routes",
			[]byte(`{"routes":["10.0.0.0/24"]}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/abc/approve_routes",
			[]byte(`{"routes":[]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeRegister(t *testing.T) {
	t.Run("happy parity", func(t *testing.T) {
		authID := types.MustAuthID()
		mk := key.NewMachine()
		nk := key.NewNode()

		seed := func(t *testing.T, app *Headscale) {
			t.Helper()

			app.state.CreateUserForTest("alice")

			regData := &types.RegistrationData{
				NodeKey:    nk.Public(),
				MachineKey: mk.Public(),
				Hostname:   "registered-node",
			}
			app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))
		}

		assertParityIsolated(t, seed, http.MethodPost,
			"/api/v1/node/register?user=alice&key="+authID.String(), nil)
	})

	t.Run("invalid key parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)
		res := h.assertParity(t, http.MethodPost,
			"/api/v1/node/register?user=alice&key=invalidkey", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost,
			"/api/v1/node/register?user=nope&key="+types.MustAuthID().String(), nil)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1NodeBackfillIPs(t *testing.T) {
	t.Run("confirmed empty parity", func(t *testing.T) {
		assertParityIsolated(t, nil, http.MethodPost,
			"/api/v1/node/backfillips?confirmed=true", nil)
	})

	t.Run("confirmed returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPost, "/api/v1/node/backfillips?confirmed=true", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"changes":[]}`, string(res.body))
	})

	t.Run("unconfirmed parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/node/backfillips", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1NodeDebugCreate(t *testing.T) {
	t.Run("unknown user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		body := []byte(`{"user":"nope","key":"` + types.MustAuthID().String() +
			`","name":"dbg","routes":[]}`)
		res := h.assertParity(t, http.MethodPost, "/api/v1/debug/node", body)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid key parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		body := []byte(`{"user":"alice","key":"badkey","name":"dbg","routes":[]}`)
		res := h.assertParity(t, http.MethodPost, "/api/v1/debug/node", body)
		assertStatus(t, res, http.StatusBadRequest)
	})

	// The handler mints fresh key material per call, so isolated apps can't
	// produce byte-identical bodies; assert the shape directly instead.
	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.app.state.CreateUserForTest("alice")

		body := []byte(`{"user":"alice","key":"` + types.MustAuthID().String() +
			`","name":"dbgnode","routes":["10.0.0.0/24"]}`)

		res := h.callHuma(http.MethodPost, "/api/v1/debug/node", body)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Node map[string]any `json:"node"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "dbgnode", got.Node["name"])
		assert.Equal(t, "REGISTER_METHOD_UNSPECIFIED", got.Node["registerMethod"])
		assert.Equal(t, []any{"10.0.0.0/24"}, got.Node["availableRoutes"])
		// The synthetic echo node has no pre-auth key: emitted as null.
		assert.Nil(t, got.Node["preAuthKey"])
		// Zero-time expiry/lastSeen are emitted as the zero instant, not null.
		assert.Equal(t, "0001-01-01T00:00:00Z", got.Node["expiry"])
		assert.Equal(t, "0001-01-01T00:00:00Z", got.Node["lastSeen"])
	})
}

// createTestAppWithPrefixV4 mirrors createTestApp but configures an IPv4
// prefix so the IP allocation and SetNodeIPv4 paths are exercised.
func createTestAppWithPrefixV4(t *testing.T, prefix string) *Headscale {
	t.Helper()

	tmpDir := t.TempDir()

	p := netip.MustParsePrefix(prefix)

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		OIDC:   types.OIDCConfig{},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
		IPAllocation: types.IPAllocationStrategySequential,
	}
	cfg.PrefixV4 = &p

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	app.mapBatcher = mapper.NewBatcherAndMapper(&cfg, app.state)
	app.mapBatcher.Start()

	t.Cleanup(func() {
		if app.mapBatcher != nil {
			app.mapBatcher.Close()
		}
	})

	return app
}

// nodeIPAddresses fetches the ipAddresses of a node through the v1 API.
func nodeIPAddresses(t *testing.T, handler http.Handler, nodeID string) []string {
	t.Helper()

	res := callHandler(handler, http.MethodGet, "/api/v1/node/"+nodeID, nil)
	require.Equal(t, http.StatusOK, res.status)

	var out struct {
		Node struct {
			IPAddresses []string `json:"ipAddresses"`
		} `json:"node"`
	}
	require.NoError(t, json.Unmarshal(res.body, &out))

	return out.Node.IPAddresses
}

// setNodeIP posts an IPv4 address to the node's IP endpoint and returns the
// status and body.
func setNodeIP(t *testing.T, handler http.Handler, nodeID, ip string) (int, []byte) {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"ipv4": ip})
	res := callHandler(handler, http.MethodPost, "/api/v1/node/"+nodeID+"/ip", body)

	return res.status, res.body
}

func setNodeIPStatus(t *testing.T, handler http.Handler, nodeID, ip string) int {
	t.Helper()

	status, _ := setNodeIP(t, handler, nodeID, ip)

	return status
}

// craftIPv4 puts a node into a state holding rawIP in the store and database
// without going through the allocator (nil clears the address), so tests can
// build edge states such as out-of-prefix addresses.
func craftIPv4(t *testing.T, app *Headscale, nodeID types.NodeID, rawIP string) {
	t.Helper()

	view, found := app.state.GetNodeByID(nodeID)
	require.True(t, found)

	node := view.AsStruct()
	if rawIP == "" {
		node.IPv4 = nil
	} else {
		parsed := netip.MustParseAddr(rawIP)
		node.IPv4 = &parsed
	}

	_, _, err := app.state.SaveNode(node.View())
	require.NoError(t, err)
}

func TestAPIV1NodeSetIP(t *testing.T) {
	t.Run("set free address releases the old one", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, app)

		require.Equal(t, []string{"100.64.1.1"}, nodeIPAddresses(t, h, "1"))
		require.Equal(t, []string{"100.64.1.2"}, nodeIPAddresses(t, h, "2"))

		status, body := setNodeIP(t, h, "1", "100.64.1.50")
		require.Equal(t, http.StatusOK, status)

		var out struct {
			Node struct {
				IPAddresses []string `json:"ipAddresses"`
			} `json:"node"`
		}
		require.NoError(t, json.Unmarshal(body, &out))
		require.Equal(t, []string{"100.64.1.50"}, out.Node.IPAddresses)

		require.Equal(t, []string{"100.64.1.50"}, nodeIPAddresses(t, h, "1"))
		// The other node is untouched.
		require.Equal(t, []string{"100.64.1.2"}, nodeIPAddresses(t, h, "2"))

		// The freed old address is assignable again: give it to node 2.
		assert.Equal(t, http.StatusOK, setNodeIPStatus(t, h, "2", "100.64.1.1"))
		require.Equal(t, []string{"100.64.1.1"}, nodeIPAddresses(t, h, "2"))
	})

	t.Run("swap addresses in use", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, app)

		// Node 2 holds 100.64.1.2, so node 1 taking it swaps the pair.
		assert.Equal(t, http.StatusOK, setNodeIPStatus(t, h, "1", "100.64.1.2"))

		require.Equal(t, []string{"100.64.1.2"}, nodeIPAddresses(t, h, "1"))
		require.Equal(t, []string{"100.64.1.1"}, nodeIPAddresses(t, h, "2"))
	})

	t.Run("swap rejected when the node has no address to hand over", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, app)

		craftIPv4(t, app, 1, "")
		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "100.64.1.2"))
	})

	t.Run("swap rejected when the previous address is out of prefix", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(
			newNodeSeed("alice", "node-a"),
			newNodeSeed("bob", "node-b"),
		)(t, app)

		craftIPv4(t, app, 1, "10.9.9.9")
		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "100.64.1.2"))
	})

	t.Run("idempotent keeps the address", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusOK, setNodeIPStatus(t, h, "1", "100.64.1.1"))
		require.Equal(t, []string{"100.64.1.1"}, nodeIPAddresses(t, h, "1"))
	})

	t.Run("out of prefix is rejected", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "10.1.2.3"))
	})

	t.Run("network address is rejected", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "100.64.1.0"))
	})

	t.Run("broadcast address is rejected", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "100.64.1.255"))
	})

	t.Run("reserved tailscale address is rejected", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.100.100.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "100.100.100.100"))
	})

	t.Run("no prefix configured is rejected", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h.huma, "1", "100.64.1.5"))
	})

	t.Run("non-IPv4 addresses are rejected", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "banana"))
		assert.Equal(t, http.StatusBadRequest, setNodeIPStatus(t, h, "1", "fd7a:115c:a1e0::1"))
	})

	t.Run("node not found", func(t *testing.T) {
		app := createTestAppWithPrefixV4(t, "100.64.1.0/24")
		h := newHumaTestHandler(app)
		seedNodes(newNodeSeed("alice", "node-a"))(t, app)

		assert.Equal(t, http.StatusNotFound, setNodeIPStatus(t, h, "9999", "100.64.1.5"))
	})
}
