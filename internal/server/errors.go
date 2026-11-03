package server

import (
	"errors"
	"net/http"

	kerrors "github.com/go-kratos/kratos/v3/errors"
	khttp "github.com/go-kratos/kratos/v3/transport/http"
	"github.com/mengbin92/user-center/internal/biz"
)

// Unexpected repository/driver errors must never become public error text.
func publicError(err error) error {
	var typed *kerrors.Error
	if errors.As(err, &typed) && typed.Reason == "CODEC" {
		return biz.Validation("请求参数不合法")
	}
	if errors.As(err, &typed) && typed.Code < 500 {
		return err
	}
	if errors.As(err, &typed) && (typed.Reason == "DEPENDENCY_UNAVAILABLE" || typed.Reason == "AUTHORIZATION_UNAVAILABLE" || typed.Reason == "OAUTH_UNAVAILABLE") {
		return err
	}
	return biz.ErrDependency
}

func encodeError(w http.ResponseWriter, r *http.Request, err error) {
	khttp.DefaultErrorEncoder(w, r, publicError(err))
}
