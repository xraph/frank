package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

var cookiename = "frank_session"

type Frank struct {
	client *ClientWithResponses
	orgId  string
	apikey string
}

func New(address string, orgId string, apikey string, opts ...ClientOption) (*Frank, error) {

	// Create a request editor for authentication
	var authFunc = func(ctx context.Context, req *http.Request) error {
		req.Header.Set("X-API-Key", apikey)
		return nil
	}

	opts = append(opts, WithRequestEditorFn(authFunc))

	c, err := NewClientWithResponses(address, opts...)
	if err != nil {
		return nil, err
	}

	return &Frank{client: c, orgId: orgId, apikey: apikey}, nil
}

func (f *Frank) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			cookie, err := r.Cookie(cookiename)
			params := &AuthMeParams{}
			if cookie != nil {
				params.FrankSid = &cookie.Value
			}

			response, err := f.client.AuthMeWithResponse(ctx, params, f.getModifier(r.Header.Get("Authorization")))
			if err != nil {
				utils.RespondError(w, err)
				return
			}

			if response.JSON200 == nil {
				utils.RespondError(w, errors.New(errors.CodeUnauthorized, "user not found"))
				return
			}

			r = r.WithContext(newCurrenUser(ctx, response.JSON200))
			next.ServeHTTP(w, r)
		})
	}
}

func (f *Frank) getModifier(token string) func(ctx context.Context, req *http.Request) error {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("X-API-Key", f.apikey)
		req.Header.Set("Authorization", token)
		return nil
	}
}

func (f *Frank) AuthMiddlewareHuma(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		octx := ctx.Context()

		cookie, _ := huma.ReadCookie(ctx, cookiename)
		params := &AuthMeParams{}
		fmt.Println("cookie.Value")
		if cookie != nil {
			fmt.Println(cookie.Value)
			params.FrankSid = &cookie.Value
		}

		response, err := f.client.AuthMeWithResponse(octx, params, f.getModifier(ctx.Header("Authorization")))
		if err != nil {
			// err = errors.New(errors.CodeUnauthorized, "unauthorized")
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"unauthorized", err,
			)
			return
		}

		if response.JSON200 == nil {
			err = errors.New(response.JSON401.Code, response.JSON401.Message)
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				response.JSON401.Message, err,
			)
			return
		}

		ctx = huma.WithValue(ctx, userCtxKey{}, response.JSON200)

		next(ctx)
	}
}

type userCtxKey struct{}

func CurrenUserFromContext(ctx context.Context) (*User, error) {
	u, ok := ctx.Value(userCtxKey{}).(*User)
	if !ok {
		return nil, errors.New(errors.CodeUnauthorized, "user id not found")
	}

	return u, nil
}

func newCurrenUser(ctx context.Context, u *User) context.Context {
	ctx = context.WithValue(ctx, userCtxKey{}, u)
	return ctx
}
