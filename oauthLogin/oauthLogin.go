package oauthLogin

import (
	"context"

	"github.com/gyarang/golang-oauth/model"
)

type loginChannel string

type oauthLogin interface {
	GetLoginUrl(state string) string
	GetMemberDataWithCode(ctx context.Context, code string) (model.User, error)
}
