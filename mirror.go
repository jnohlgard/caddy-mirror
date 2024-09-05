package mirror

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net/http"
)

func init() {
	caddy.RegisterModule(Mirror{})
}

type Mirror struct {
	// The path to the root of the site. Default is `{http.vars.root}` if set,
	// or current working directory otherwise. This should be a trusted value.
	//
	// Note that a site root is not a sandbox. Although the file server does
	// sanitize the request URI to prevent directory traversal, files (including
	// links) within the site root may be directly accessed based on the request
	// path. Files and folders within the root should be secure and trustworthy.
	//
	// Responses from upstreams will be written to files within this root directory to be used as a local mirror of static content
	Root string `json:"root,omitempty"`

	// File name suffix to add to write Etags to.
	// If set, file Etags will be written to sidecar files
	// with this suffix.
	EtagFileSuffix string `json:"etag_file_suffix,omitempty"`

	logger *zap.Logger
}

func (Mirror) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.mirror",
		New: func() caddy.Module { return new(Mirror) },
	}
}

// Provision sets up the mirror handler
func (mir *Mirror) Provision(ctx caddy.Context) error {
	mir.logger = ctx.Logger()
	if mir.Root == "" {
		mir.Root = "{http.vars.root}"
	}
	return nil
}

func (mir *Mirror) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Mirror)(nil)
	_ caddyhttp.MiddlewareHandler = (*Mirror)(nil)
)
