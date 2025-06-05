package frank

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/utils"
)

func (f *Frank) AuthMiddleware() func(http.Handler) http.Handler {
	authmw := middleware.AuthGoa(f.cfg, f.log, f.Services.Session, f.Services.SessionStore, f.Services.APIKey, f.Services.CookieHandler)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := authmw.AuthWithOptionsGoa()(r.Context(), "", nil)
			if err != nil {
				utils.RespondError(w, err)
				return
			}
			r = r.WithContext(newCurrenUserID(ctx))
			next.ServeHTTP(w, r)
		})
	}
}

func (f *Frank) AuthMiddlewareHuma(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	authmw := middleware.AuthGoa(f.cfg, f.log, f.Services.Session, f.Services.SessionStore, f.Services.APIKey, f.Services.CookieHandler)
	return func(ctx huma.Context, next func(huma.Context)) {
		// Wrap the context to add a value.
		octx, err := authmw.AuthWithOptionsGoa()(ctx.Context(), "", nil)
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"unauthorized", err,
			)
			return
		}

		id, ok := middleware.GetUserID(octx)
		if !ok {
			err = errors.New(errors.CodeUnauthorized, "user id not found")
			huma.WriteErr(api, ctx, http.StatusNotFound,
				"user id not found", err,
			)
		}
		ctx = huma.WithValue(ctx, userCtxKey{}, id)

		next(ctx)
	}
}

type userCtxKey struct{}

func CurrenUserID(ctx context.Context) (string, error) {
	id, ok := ctx.Value(userCtxKey{}).(string)
	if !ok {
		return "", errors.New(errors.CodeUnauthorized, "user id not found")
	}

	return id, nil
}

func newCurrenUserID(ctx context.Context) context.Context {
	id, ok := middleware.GetUserID(ctx)
	if ok {
		ctx = context.WithValue(ctx, userCtxKey{}, id)
	}
	return ctx
}
