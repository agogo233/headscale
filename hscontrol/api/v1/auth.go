package apiv1

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func init() {
	registrations = append(registrations, registerAuth)
}

// errAuthRejected is the verdict handed to the waiting registration flow when
// an auth session is rejected.
var errAuthRejected = errors.New("auth request rejected")

// AuthRegisterRequestBody is the v1.AuthRegisterRequest body.
type AuthRegisterRequestBody struct {
	User   string `json:"user,omitempty"`
	AuthID string `json:"authId,omitempty"`
}

// AuthApproveRequestBody is the v1.AuthApproveRequest body.
type AuthApproveRequestBody struct {
	AuthID string `json:"authId,omitempty"`
}

// AuthRejectRequestBody is the v1.AuthRejectRequest body.
type AuthRejectRequestBody struct {
	AuthID string `json:"authId,omitempty"`
}

type (
	authRegisterInput struct {
		Body AuthRegisterRequestBody
	}
	authRegisterOutput struct {
		Body struct {
			Node Node `json:"node"`
		}
	}
)

type (
	authApproveInput struct {
		Body AuthApproveRequestBody
	}
	authApproveOutput struct {
		Body struct{}
	}
)

type (
	authRejectInput struct {
		Body AuthRejectRequestBody
	}
	authRejectOutput struct {
		Body struct{}
	}
)

// PendingAuthRequest is the v1 list item for an open node-registration request
// waiting for an auth verdict.
type PendingAuthRequest struct {
	AuthID      string    `json:"authId"`
	Hostname    string    `json:"hostname"`
	User        string    `json:"user"`
	OS          string    `json:"os"`
	OSVersion   string    `json:"osVersion"`
	RoutableIPs []string  `json:"routableIPs" nullable:"false"`
	CreatedAt   time.Time `json:"createdAt"`
}

type (
	listPendingAuthRequestsOutput struct {
		Body struct {
			AuthRequests []PendingAuthRequest `json:"authRequests" nullable:"false"`
		}
	}
)

func registerAuth(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "authRegister",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/register",
		Summary:     "Register node via auth flow",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authRegisterInput) (*authRegisterOutput, error) {
		// Malformed auth_id is 400; unknown user and missing pending session are
		// 404 via mapError, matching the Approve/Reject handlers.
		registrationID, err := types.AuthIDFromString(in.Body.AuthID)
		if err != nil {
			return nil, huma.Error400BadRequest("registering node", err)
		}

		// Numeric user values are ids, anything else a username.
		user, err := resolveUserByIDOrName(b, in.Body.User)
		if err != nil {
			return nil, err
		}

		node, nodeChange, err := b.State.HandleNodeFromAuthPath(
			registrationID,
			types.UserID(user.ID),
			nil,
			util.RegisterMethodCLI,
		)
		if err != nil {
			b.Change(nodeChange)

			return nil, mapError("registering node", err)
		}

		routeChange, err := b.State.AutoApproveRoutes(node)
		b.Change(nodeChange, routeChange)

		if err != nil {
			return nil, huma.Error500InternalServerError("auto approving routes", err)
		}

		out := &authRegisterOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "authApprove",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/approve",
		Summary:     "Approve a pending auth session",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authApproveInput) (*authApproveOutput, error) {
		authReq, err := pendingAuthRequest(b, in.Body.AuthID)
		if err != nil {
			return nil, err
		}

		authReq.FinishAuth(types.AuthVerdict{})

		return &authApproveOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "authReject",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/reject",
		Summary:     "Reject a pending auth session",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authRejectInput) (*authRejectOutput, error) {
		authReq, err := pendingAuthRequest(b, in.Body.AuthID)
		if err != nil {
			return nil, err
		}

		authReq.FinishAuth(types.AuthVerdict{
			Err: errAuthRejected,
		})

		return &authRejectOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listPendingAuthRequests",
		Method:      http.MethodGet,
		Path:        "/api/v1/auth/pending",
		Summary:     "List pending auth requests",
		Description: "Lists open node-registration requests waiting for an auth verdict.",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listPendingAuthRequestsOutput, error) {
		entries := b.State.ListPendingAuthRequests()

		out := &listPendingAuthRequestsOutput{}
		out.Body.AuthRequests = make([]PendingAuthRequest, 0, len(entries))

		for _, entry := range entries {
			out.Body.AuthRequests = append(out.Body.AuthRequests,
				pendingAuthRequestFromEntry(b, entry),
			)
		}

		return out, nil
	})
}

// pendingAuthRequestFromEntry builds one list item from a cached pending
// request. User is only known after the OIDC callback resolved the identity,
// and the routable-IP field stays empty until the client announced it.
func pendingAuthRequestFromEntry(
	b Backend,
	entry types.AuthRequestEntry,
) PendingAuthRequest {
	reg := entry.Request.RegistrationData()

	item := PendingAuthRequest{
		AuthID:    entry.ID.String(),
		Hostname:  reg.Hostname,
		CreatedAt: entry.Request.CreatedAt(),
	}

	if reg.Hostinfo != nil {
		item.OS = reg.Hostinfo.OS
		item.OSVersion = reg.Hostinfo.OSVersion

		for _, prefix := range reg.Hostinfo.RoutableIPs {
			item.RoutableIPs = append(item.RoutableIPs, prefix.String())
		}
	}

	if item.RoutableIPs == nil {
		item.RoutableIPs = []string{}
	}

	if pc := entry.Request.PendingConfirmation(); pc != nil {
		if user, err := b.State.GetUserByID(types.UserID(pc.UserID)); err == nil {
			item.User = user.Name

			if item.User == "" {
				item.User = user.Username()
			}
		}
	}

	return item
}

// pendingAuthRequest looks up the pending session for auth_id. Malformed
// auth_id is 400, unknown is 404.
func pendingAuthRequest(b Backend, rawID string) (*types.AuthRequest, error) {
	authID, err := types.AuthIDFromString(rawID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid auth_id", err)
	}

	authReq, ok := b.State.GetAuthCacheEntry(authID)
	if !ok {
		return nil, huma.Error404NotFound("no pending auth session for auth_id " + authID.String())
	}

	return authReq, nil
}
