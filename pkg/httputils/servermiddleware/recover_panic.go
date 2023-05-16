package servermiddleware

import (
	"fmt"
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
			if ev := errmon.ObserveRecoverCtx(request.Context(), recover()); ev != nil {
				fmt.Println(ev.StackTrace.String()) // TODO: remove this line, ObserveRecoverCtx should report the stacktrace by itself!
			}
		}()
		handler(response, request)
	}
}
