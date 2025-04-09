package sdk

import (
	"context"
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

			cookieString := r.Header.Get("Cookie")
			u, err := f.getLoggedInUser(ctx, r.Header.Get("Authorization"), cookieString, cookie)
			if err != nil {
				utils.RespondError(w, err)
				return
			}

			r = r.WithContext(newCurrenUser(ctx, u))
			next.ServeHTTP(w, r)
		})
	}
}

func (f *Frank) getModifier(token string, cookies string) func(ctx context.Context, req *http.Request) error {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("X-API-Key", f.apikey)
		req.Header.Set("Authorization", token)
		req.Header.Set("Cookie", cookies)
		return nil
	}
}

func (f *Frank) getLoggedInUser(ctx context.Context, token string, cookies string, cookie *http.Cookie) (*User, error) {
	params := &AuthMeParams{}
	if cookie != nil {
		params.FrankSid = &cookie.Value
	}

	response, err := f.client.AuthMeWithResponse(ctx, params, f.getModifier(token, cookies))
	if err != nil {
		return nil, errors.New(errors.CodeUnauthorized, "unauthorized")
	}
	if response.JSON200 == nil {
		return nil, errors.New(response.JSON401.Code, response.JSON401.Message)
	}

	return response.JSON200, nil
}

func (f *Frank) AuthMiddlewareHuma(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		octx := ctx.Context()
		cookie, _ := huma.ReadCookie(ctx, cookiename)
		cookieString := ctx.Header("Cookie")

		u, err := f.getLoggedInUser(octx, ctx.Header("Authorization"), cookieString, cookie)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"unauthorized", err,
			)
			return
		}

		ctx = huma.WithValue(ctx, userCtxKey{}, u)

		next(ctx)
	}
}

type userCtxKey struct{}

func CurrenUserFromContext(ctx context.Context) (*User, error) {
	u, ok := ctx.Value(userCtxKey{}).(*User)
	if !ok || u == nil {
		return nil, errors.New(errors.CodeUnauthorized, "user id not found")
	}

	return u, nil
}

func newCurrenUser(ctx context.Context, u *User) context.Context {
	ctx = context.WithValue(ctx, userCtxKey{}, u)
	return ctx
}
