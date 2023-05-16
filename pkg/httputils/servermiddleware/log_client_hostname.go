package servermiddleware

import (
	"net/http"

	"github.com/facebookincubator/go-belt/beltctx"
)

// HTTPHeaderNameLogClientHostname is the name of a HTTP reader used to
// pass through the client name (to be used in logs on the server side as
// field "client_hostname").
const HTTPHeaderNameLogClientHostname = `X-Log-Client-Hostname`

// LogClientHostname is a server interceptor to log additional information, based
// on special HTTP readers
//
// Should be executed only after SetupContext, otherwise it will panic.
func LogClientHostname(
	handler func(http.ResponseWriter, *http.Request),
) func(http.ResponseWriter, *http.Request) {
	return func(response http.ResponseWriter, request *http.Request) {
		if clientHostname, ok := request.Header[HTTPHeaderNameLogClientHostname]; ok {
			ctx := request.Context()
			ctx = beltctx.WithField(ctx, "client_hostname", clientHostname)
			request = request.WithContext(ctx)
		}
		handler(response, request)
	}
}
