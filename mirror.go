package mirror

import (
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
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
	if r.Method != http.MethodGet {
		mir.logger.Debug("Ignore non-GET request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path))
		return next.ServeHTTP(w, r)
	}
	urlp := r.URL.Path
	if !path.IsAbs(urlp) {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("URL path %v not absolute", urlp))
	}
	if strings.HasSuffix(urlp, "/") {
		// Pass through directory requests unmodified
		mir.logger.Debug("skip directory browse",
			zap.String("request_path", urlp))
		return next.ServeHTTP(w, r)
	}

	// Replace any Caddy placeholders in Root
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	root := repl.ReplaceAll(mir.Root, ".")
	filename := mir.locateMirrorFile(root, urlp)
	mirrorFileExists, err := mir.validateMirrorTarget(filename)
	if err != nil {
		if errors.Is(err, ErrIsDir) {
			mir.logger.Debug("skip directory",
				zap.String("site_root", root),
				zap.String("request_path", urlp),
				zap.String("filename", filename),
			)
			return next.ServeHTTP(w, r)
		} else if errors.Is(err, fs.ErrNotExist) {

		} else if errors.Is(err, fs.ErrPermission) {
			mir.logger.Debug("mirror file permission error, return 403",
				zap.String("site_root", root),
				zap.String("request_path", urlp),
				zap.String("filename", filename),
				zap.Error(err))
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		return err
	}
	if mirrorFileExists {
		mir.logger.Debug("mirror file already exists",
			zap.String("site_root", root),
			zap.String("request_path", urlp),
			zap.String("filename", filename),
		)
	} else {
		mir.logger.Debug("creating temp file", zap.String("filename", filename))
		incomingFile, err := NewIncomingFile(filename)
		if err != nil {
			mir.logger.Error("failed to create temp file",
				zap.String("site_root", root),
				zap.String("request_path", urlp),
				zap.String("filename", filename),
				zap.Error(err))
			if errors.Is(err, fs.ErrPermission) {
				return caddyhttp.Error(http.StatusForbidden,
					fmt.Errorf("unable to mirror %v as %v: %w", urlp, filename, err))
			}
			return err
		}
		defer func(af *IncomingFile) {
			mir.logger.Debug("closing temp file",
				zap.String("site_root", root),
				zap.String("request_path", urlp),
				zap.String("orig_file", filename),
				zap.String("temp_file", af.Name()),
			)
			err := af.Close()
			if err != nil {
				mir.logger.Error("error when closing temp file",
					zap.String("site_root", root),
					zap.String("request_path", urlp),
					zap.String("orig_file", filename),
					zap.String("temp_file", af.Name()),
					zap.Error(err))
			}
		}(incomingFile)

		rww := &responseWriterWrapper{
			ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
			file:                  incomingFile,
			config:                mir,
		}
		w = rww
		defer func(w *responseWriterWrapper) {
			mir.logger.Debug("responseWriterWrapper leaving",
				zap.String("site_root", root),
				zap.String("request_path", urlp),
				zap.Bool("aborted", rww.file.aborted),
				zap.Bool("complete", rww.file.complete),
				zap.Bool("done", rww.file.done),
				zap.Int64("bytes_expected", rww.bytesExpected),
				zap.Int64("bytes_written", rww.bytesWritten),
			)
		}(rww)
	}

	return next.ServeHTTP(w, r)
}

var ErrIsDir = errors.New("file is a directory")

// Returns true if the file exists and is a regular file, false otherwise
func (mir *Mirror) validateMirrorTarget(filename string) (bool, error) {
	stat, err := os.Lstat(filename)
	if err != nil {
		// fs.ErrNotExist is expected when we have not mirrored this path before
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	} else if stat.Mode().IsDir() {
		// Skip directories
		return false, &fs.PathError{
			Op:   "locate mirror copy",
			Path: filename,
			Err:  ErrIsDir,
		}
	} else if !stat.Mode().IsRegular() {
		mir.logger.Error("local mirror is not a file!!",
			zap.String("filename", filename),
			zap.String("fileinfo", fs.FormatFileInfo(stat)))

		return false, caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("file %v is not a file", filename))
	}
	return true, nil
}

func (mir *Mirror) locateMirrorFile(root string, urlp string) string {
	// Figure out the local path of the given URL path
	filename := strings.TrimSuffix(caddyhttp.SanitizedPathJoin(root, urlp), "/")
	mir.logger.Debug("sanitized path join",
		zap.String("site_root", root),
		zap.String("request_path", urlp),
		zap.String("result", filename))
	return filename
}

type responseWriterWrapper struct {
	*caddyhttp.ResponseWriterWrapper
	file          *IncomingFile
	config        *Mirror
	bytesExpected int64
	bytesWritten  int64
}

func (rww *responseWriterWrapper) Write(data []byte) (int, error) {
	// ignore zero data writes
	if rww.file.aborted || len(data) == 0 {
		return rww.ResponseWriter.Write(data)
	}
	var written = 0
	defer func() {
		rww.bytesWritten += int64(written)
		if rww.bytesExpected > 0 && rww.bytesWritten == rww.bytesExpected {
			rww.config.logger.Debug("responseWriterWrapper fully written",
				zap.Int64("bytes_written", rww.bytesWritten),
				zap.Int64("bytes_expected", rww.bytesExpected),
			)
			err := rww.file.Complete()
			if err != nil {
				rww.config.logger.Error("failed to complete responseWriterWrapper", zap.Error(err))
			}
		}
	}()
	for {
		// Write out the data buffer to the mirror target first
		n, err := rww.file.Write(data)
		written += n
		if err != nil && !errors.Is(err, io.ErrShortWrite) {
			return written, err
		}

		if written == len(data) {
			// Continue by passing the buffer on to the next ResponseWriter in the chain
			return rww.ResponseWriter.Write(data)
		}
	}
}

func (rww *responseWriterWrapper) WriteHeader(statusCode int) {
	if statusCode == http.StatusOK {
		// Get the Content-Length header to figure out how much data to expect
		cl, err := strconv.ParseInt(rww.Header().Get("Content-Length"), 10, 64)
		if err == nil {
			rww.bytesExpected = cl
		}
	} else {
		// Avoid writing error messages and such to disk
		err := rww.file.Abort()
		if err != nil {
			rww.config.logger.Error("failed to abort IncomingFile",
				zap.String("site_root", rww.config.Root),
				zap.String("filename", rww.file.Name()),
				zap.Error(err))
		}
	}
	rww.ResponseWriter.WriteHeader(statusCode)
}

func (af *IncomingFile) Close() error {
	if af.done {
		return nil
	}
	if !af.complete {
		return af.Abort()
	}
	if !af.closed {
		// Important to fsync before renaming to avoid risking a 0 byte destination file
		if err := af.Sync(); err != nil {
			return err
		}
		if err := af.File.Close(); err != nil {
			return err
		}
		af.closed = true
	}
	err := os.Rename(af.File.Name(), af.target)
	if err != nil {
		return err
	}
	af.done = true
	return nil
}

func (af *IncomingFile) Complete() error {
	if af.aborted {
		return fmt.Errorf("file already aborted")
	}
	af.complete = true
	return nil
}

func (af *IncomingFile) Abort() error {
	if af.done {
		return nil
	}
	af.aborted = true
	if err := af.File.Close(); err != nil {
		return err
	}
	af.closed = true
	if err := os.Remove(af.File.Name()); err != nil {
		return err
	}
	af.done = true
	return nil
}

func NewIncomingFile(path string) (*IncomingFile, error) {
	dir, base := filepath.Split(path)
	if err := os.MkdirAll(dir, mkdirPerms); err != nil {
		return nil, err
	}
	stat, err := os.Lstat(path)
	if err == nil {
		if !stat.Mode().IsRegular() {
			return nil, &fs.PathError{
				Op:   "NewIncomingFile",
				Path: path,
				Err:  errors.New("target is not a regular file"),
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	temp, err := os.CreateTemp(dir, "._tmp_"+base)
	if err != nil {
		return nil, err
	}
	if stat != nil {
		ts, err := temp.Stat()
		if err != nil {
			_ = temp.Close()
			return nil, err
		}
		if ts.Mode().Perm() != stat.Mode().Perm() {
			err := temp.Chmod(stat.Mode().Perm())
			if err != nil {
				return nil, err
			}
		}
	}
	return &IncomingFile{
		File:   temp,
		target: path,
	}, nil
}

type IncomingFile struct {
	*os.File
	target   string
	complete bool
	done     bool
	closed   bool
	aborted  bool
}

const (
	// mode before umask is applied
	mkdirPerms fs.FileMode = 0o777
)

// Interface guards
var (
	_ caddy.Provisioner           = (*Mirror)(nil)
	_ caddyhttp.MiddlewareHandler = (*Mirror)(nil)
)
