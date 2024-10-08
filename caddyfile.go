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
	httpcaddyfile.RegisterHandlerDirective("mirror", parseHandler)
	httpcaddyfile.RegisterGlobalOption("mirror", parseOption)
	httpcaddyfile.RegisterDirectiveOrder("mirror", httpcaddyfile.Before, "reverse_proxy")
}

// parseOption parses the mirror global option block
func parseOption(d *caddyfile.Dispenser, _ any) (any, error) {
	mir := new(Mirror)
	err := mir.UnmarshalCaddyfile(d)
	if err != nil {
		return mir, err
	}
	return mir, err
}

// parseHandler parses the mirror handler directive.
// See UnmarshalCaddyfile for the syntax.
func parseHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	mir := new(Mirror)
	globalOptions := h.Option("mirror").(*Mirror)
	if globalOptions != nil {
		*mir = *globalOptions
	}
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
//	    xattr             [<bool>]
//	    sha256            xattr
//	}
func (mir *Mirror) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.CountRemainingArgs() > 0 {
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
					mir.Sha256Xattr = mir.Sha256Xattr && val
				} else {
					return d.WrapErr(err)
				}
			default:
				return d.ArgErr()
			}
		case "sha256":
			args := d.RemainingArgs()
			switch len(args) {
			case 1:
				if args[0] == "xattr" {
					mir.UseXattr = true
					mir.Sha256Xattr = true
				} else {
					return d.Err("sha256 only supports xattr at the moment")
				}
			default:
				return d.ArgErr()
			}
		case "hide_temp_files":
			if d.CountRemainingArgs() > 0 {
				return d.ArgErr()
			}
			mir.HideTempFiles = true
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}
	return nil
}

// Validate validates that the module has a usable config.
func (mir Mirror) Validate() error {
	if mir.Sha256Xattr && !mir.UseXattr {
		return errors.New("sha256 xattr requires xattr enabled")
	}
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
