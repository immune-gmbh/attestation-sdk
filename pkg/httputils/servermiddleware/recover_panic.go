package servermiddleware

import (
	"net/http"

	"github.com/facebookincubator/go-belt/tool/experimental/errmon"
)

// RecoverPanic recovers panics and logs them through the extended context
// handler.
//
// Should be executed only after SetupContext.
func RecoverPanic(
	handler func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		defer func() {
			errmon.ObserveRecoverCtx(request.Context(), recover())
		}()
		handler(response, request)
	}
}
