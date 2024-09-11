package mirror

import (
	"errors"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pkg/xattr"
	"strconv"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("mirror", parseCaddyfile)
	httpcaddyfile.RegisterGlobalOption("mirror", parseCaddyfileOption)
}

func parseCaddyfileOption(d *caddyfile.Dispenser, val any) (any, error) {
	return nil, nil
}

// parseCaddyfile parses the mirror directive.
// See UnmarshalCaddyfile for the syntax.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	mir := new(Mirror)
	err := mir.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return mir, err
	}
	return mir, err
}

// UnmarshalCaddyfile parses the mirror directive. It enables
// the static mirror writer and configures it with this syntax:
//
//	mirror [<matcher>] [<root>] {
//	    root              <path>
//	    etag_file_suffix  <suffix>
//	}
func (mir *Mirror) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	args := d.RemainingArgs()
	switch len(args) {
	case 0:
	case 1:
		mir.Root = args[0]
	default:
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "root":
			if !d.Args(&mir.Root) {
				return d.ArgErr()
			}
		case "etag_file_suffix":
			if !d.Args(&mir.EtagFileSuffix) {
				return d.ArgErr()
			}
		case "xattr":
			args := d.RemainingArgs()
			switch len(args) {
			case 0:
				mir.UseXattr = true
			case 1:
				if val, err := strconv.ParseBool(args[0]); err == nil {
					mir.UseXattr = val
				} else {
					return d.WrapErr(err)
				}
			default:
				return d.ArgErr()
			}
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}
	return nil
}

// Validate validates that the module has a usable config.
func (mir Mirror) Validate() error {
	if mir.UseXattr && !xattr.XATTR_SUPPORTED {
		return errors.New("missing platform xattr support")
	}
	return nil
}

// Interface guards
var (
	_ caddy.Validator       = (*Mirror)(nil)
	_ caddyfile.Unmarshaler = (*Mirror)(nil)
)
