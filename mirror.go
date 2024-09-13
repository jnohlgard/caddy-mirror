package mirror

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/renameio/v2"
	"github.com/pkg/xattr"
	"go.uber.org/zap"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
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

	// File name suffix to add to write ETags to.
	// If set, file ETags will be written to sidecar files
	// with this suffix.
	EtagFileSuffix string `json:"etag_file_suffix,omitempty"`

	UseXattr bool `json:"xattr,omitempty"`

	Sha256Xattr bool `json:"sha256_xattr,omitempty"`

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
	logger := mir.logger.With(zap.String("site_root", root),
		zap.String("request_path", urlp))
	filename := mir.pathInsideRoot(root, urlp)
	existingFile, err := openRegularFile(filename)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// ErrNotExist is expected if this path is not yet mirrored
		if errors.Is(err, ErrIsDir) {
			logger.Debug("skip local directory")
			return next.ServeHTTP(w, r)
		} else if errors.Is(err, ErrNotRegular) {
			logger.Error("local mirror is not a file!!",
				zap.Error(err))
			return caddyhttp.Error(http.StatusForbidden, err)
		} else if errors.Is(err, fs.ErrPermission) {
			logger.Error("mirror file permission error",
				zap.Error(err))
			return caddyhttp.Error(http.StatusForbidden, err)
		}
	}
	if existingFile != nil {
		defer existingFile.Close()
		logger.Debug("mirror file opened for reading")
		stat, _ := existingFile.Stat()
		var modtime time.Time
		if stat != nil {
			modtime = stat.ModTime()
		}

		if w.Header().Get("ETag") == "" {
			// Check if we have any ETag sources for this mirror file
			var fileEtags []string
			// Check if there are any xattrs set on the mirror file
			if f, ok := existingFile.(*os.File); ok {
				if mir.Sha256Xattr {
					if etag := etagFromXattr(f, "user.xdg.origin.sha256"); etag != "" {
						fileEtags = append(fileEtags, etag)
					}
				}
				if mir.UseXattr {
					if etag := etagFromXattr(f, "user.xdg.origin.etag"); etag != "" {
						fileEtags = append(fileEtags, etag)
					}
				}
			}
			// Check if we have a sidecar file with an ETag
			if mir.EtagFileSuffix != "" {
				etag, err := etagFromFile(filename + mir.EtagFileSuffix)
				if err != nil {
					logger.Warn("etag from file failed", zap.Error(err))
				} else if etag != "" {
					fileEtags = append(fileEtags, etag)
				}
			}
			logger.Debug("mirror file ETag candidates",
				zap.Strings("file_etags", fileEtags))
			if len(fileEtags) == 0 && stat != nil {
				// Generate an ETag from the file size and modification time
				etag := etagFromFileInfo(stat)
				if etag != "" {
					fileEtags = append(fileEtags, etag)
				}
			}
			if len(fileEtags) == 1 {
				w.Header().Set("ETag", fileEtags[0])
			}
			if len(fileEtags) > 1 {
				// We need to figure out which of these ETags that our client might be asking for
				for _, header := range []string{"If-None-Match", "If-Range", "If-Match"} {
					etag := findEtagsInHeader(r, header, fileEtags)
					if etag != "" {
						w.Header().Set("ETag", etag)
						break
					}
				}
				if w.Header().Get("ETag") == "" {
					// Nothing matched, pick the first from the above generated list.
					w.Header().Set("ETag", fileEtags[0])
				}
			}
			logger.Debug("content ETag",
				zap.String("ETag", w.Header().Get("ETag")))
		}
		logger.Debug("serving content to client",
			zap.Object("headers", caddyhttp.LoggableHTTPHeader{
				Header: w.Header(),
			}),
		)
		// Like the Caddy file_server implementation, we will let the standard library handle actually writing the right ranges to the client.
		http.ServeContent(w, r, filename, modtime, existingFile.(io.ReadSeeker))
		return nil
	} else {
		logger.Debug("creating temp file")
		incomingFile, err := createTempFile(filename)
		if err != nil {
			logger.Error("failed to create temp file",
				zap.Error(err))
			if errors.Is(err, fs.ErrPermission) {
				return caddyhttp.Error(http.StatusForbidden, err)
			}
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		defer incomingFile.Cleanup()
		rww := &responseWriterWrapper{
			ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
			file:                  incomingFile,
			config:                mir,
			logger:                logger.With(zap.Namespace("rww")),
		}

		if mir.EtagFileSuffix != "" {
			etagFilename := filename + mir.EtagFileSuffix
			etagFile, err := createTempFile(etagFilename)
			if err != nil {
				logger.Error("failed to create ETag temp file, continuing without writing ETag sidecar file",
					zap.Error(err))
			} else {
				defer etagFile.Cleanup()
				rww.etagFile = etagFile
			}
		}
		w = rww
	}

	return next.ServeHTTP(w, r)
}

// findEtagsInHeader looks for any of the given ETag values within the given header
func findEtagsInHeader(r *http.Request, header string, etags []string) string {
	for _, etag := range splitQuotedFields(r.Header.Get(header)) {
		if etag != "" {
			if slices.Contains(etags, etag) {
				return etag
			}
		}
	}
	return ""
}

// splitQuotedFields splits an input string of comma-separated double-quoted values into separate strings for each value
// The surrounding double quotes will be left intact in the resulting values.
func splitQuotedFields(s string) (fields []string) {
	fields = make([]string, 0)
	quoted := false
	start := 0
	for end, val := range s {
		if val == '"' {
			quoted = !quoted
		} else if val == ',' {
			if !quoted && start < end {
				fields = append(fields, textproto.TrimString(s[start:end]))
				start = end + 1
			}
		}
	}
	if !quoted && start < len(s) {
		fields = append(fields, textproto.TrimString(s[start:]))
	}
	return fields
}

// etagFromFileInfo calculates the ETag based on file size and modification time the same way as done by the Caddy
// builtin file_server directive
func etagFromFileInfo(stat fs.FileInfo) string {
	mtime := stat.ModTime()
	if mtimeUnix := mtime.Unix(); mtimeUnix == 0 || mtimeUnix == 1 {
		return "" // not useful anyway; see issue #5548
	}
	var sb strings.Builder
	sb.WriteRune('"')
	sb.WriteString(strconv.FormatInt(mtime.UnixNano(), 36))
	sb.WriteString(strconv.FormatInt(stat.Size(), 36))
	sb.WriteRune('"')
	return sb.String()
}

func etagFromFile(filename string) (string, error) {
	f, openErr := openRegularFile(filename)
	defer f.Close()
	if openErr != nil {
		return "", openErr
	}
	// DoS prevention: Avoid reading excessively large etag files
	buf := make([]byte, 512)
	n, readErr := f.Read(buf)
	_ = f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", readErr
	}
	if n >= len(buf) {
		return "", fmt.Errorf("eTag sidecar file too big, read %v bytes", n)
	}
	return formatEtag(buf[:n]), nil
}

func etagFromXattr(file *os.File, name string) string {
	buf, err := xattr.FGet(file, name)
	if err == nil {
		return formatEtag(buf)
	}
	return ""
}

// formatEtag filters the bytes in data into a properly formatted ETag entry, including adding surrounding double quotes if missing.
// If data contains no usable characters, the empty string is returned (i.e. without any double quotes)
func formatEtag(data []byte) (etag string) {
	if len(data) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteRune('"')
	n := 0
	for _, val := range data {
		// https://httpwg.org/specs/rfc9110.html#field.etag
		if val < '\x21' || val == '\x22' || '\x7e' < val {
			// Filter out all control chars, whitespace, double quotes, and anything beyond basic ASCII
			continue
		}
		sb.WriteRune(rune(val))
		n++
	}
	if n == 0 {
		return ""
	}
	sb.WriteRune('"')
	return sb.String()
}

var ErrNotRegular = errors.New("file is not a regular file")
var ErrIsDir = errors.New("file is a directory")

// openRegularFile opens a file and checks if the file is a regular file (no type bits are set)
// ErrIsDir or ErrNotRegular is returned if filename exists and is not a regular file.
func openRegularFile(filename string) (file fs.File, err error) {
	// O_NOFOLLOW to avoid following symlinks in the final component of the file name
	file, err = os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	keepOpen := false
	defer func(file fs.File) {
		if !keepOpen {
			_ = file.Close()
		}
	}(file)
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	} else if stat.Mode().IsDir() {
		return nil, &fs.PathError{
			Op:   "openRegularFile",
			Path: filename,
			Err:  fmt.Errorf("%w: %w (%v)", ErrNotRegular, ErrIsDir, fs.FormatFileInfo(stat)),
		}
	} else if !stat.Mode().IsRegular() {
		return nil, &fs.PathError{
			Op:   "openRegularFile",
			Path: filename,
			Err:  fmt.Errorf("%w (%v)", ErrNotRegular, fs.FormatFileInfo(stat)),
		}
	} else {
		keepOpen = true
	}
	return file, nil
}

func (mir *Mirror) pathInsideRoot(root string, urlp string) string {
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
	file          *renameio.PendingFile
	etagFile      *renameio.PendingFile
	config        *Mirror
	logger        *zap.Logger
	bytesExpected int64
	bytesWritten  int64
	contentHash   hash.Hash
}

func (rww *responseWriterWrapper) writeDone(written int64) {
	rww.bytesWritten += written
	if rww.bytesExpected > 0 && rww.bytesWritten == rww.bytesExpected {
		rww.logger.Debug("responseWriterWrapper fully written",
			zap.Int64("bytes_written", rww.bytesWritten),
			zap.Int64("bytes_expected", rww.bytesExpected),
		)
		rww.finalize()
	}
}

func (rww *responseWriterWrapper) finalize() {
	if rww.contentHash != nil {
		sum := rww.contentHash.Sum(nil)
		sumText := hex.EncodeToString(sum)
		rww.logger.Debug("hash done", zap.String("sum", sumText))
		if rww.config.Sha256Xattr {
			err := xattr.FSet(rww.file.File, "user.xdg.origin.sha256", []byte(sumText))
			if err != nil {
				rww.logger.Error("failed to set sha256 xattr",
					zap.Binary("sha256", sum),
					zap.Error(err))
			}
		}
	}
	err := rww.file.CloseAtomicallyReplace()
	if err != nil {
		rww.logger.Error("failed to complete mirror file",
			zap.Error(err))
		return
	} else if rww.etagFile != nil {
		err := rww.etagFile.CloseAtomicallyReplace()
		if err != nil {
			rww.logger.Error("failed to complete etagFile",
				zap.Error(err))
		}
	}
}

// writeAll writes to w from data[], retrying until all of data[] has been consumed, unless an error other than ErrShortWrite occurs
func writeAll(w io.Writer, data []byte) (int, error) {
	written := 0
	for {
		// Keep going until we are not making any more progress
		n, err := w.Write(data[written:])
		written += n
		if written > len(data) {
			panic("wrote more than len(data)!!!")
		}
		if n == 0 {
			if err == nil {
				err = io.ErrShortWrite
			}
			return written, fmt.Errorf("not making progress: %w", err)
		}
		if written == len(data) {
			break
		}
	}
	return written, nil
}

func (rww *responseWriterWrapper) Write(data []byte) (int, error) {
	// ignore zero data writes
	if len(data) == 0 {
		return rww.ResponseWriter.Write(data)
	}
	if rww.contentHash != nil {
		hashed, err := writeAll(rww.contentHash, data)
		if err != nil {
			rww.logger.Error("failed to hash data",
				zap.Int("bytes_hashed", hashed),
				zap.Error(err))
			rww.contentHash = nil
		}
	}
	written, err := writeAll(rww.file, data)
	rww.writeDone(int64(written))
	if err != nil {
		return written, err
	}
	// Continue by passing the buffer on to the next ResponseWriter in the chain
	return rww.ResponseWriter.Write(data)
}

func (rww *responseWriterWrapper) WriteHeader(statusCode int) {
	if statusCode == http.StatusOK {
		// Get the Content-Length header to figure out how much data to expect
		cl, err := strconv.ParseInt(rww.Header().Get("Content-Length"), 10, 64)
		if err == nil {
			rww.bytesExpected = cl
		}
		etag := rww.Header().Get("ETag")
		if etag != "" {
			// Store ETag as xattr
			if rww.config.UseXattr {
				err := xattr.FSet(rww.file.File, "user.xdg.origin.etag", []byte(etag))
				if err != nil {
					rww.logger.Error("failed to write ETag to xattr",
						zap.Error(err))
				}
			}
			// Store ETag as separate file
			if rww.etagFile != nil {
				_, err := io.Copy(rww.etagFile, strings.NewReader(etag))
				if err != nil {
					rww.logger.Error("failed to write temp ETag file",
						zap.Error(err))
				}
			}
		}
		if rww.config.Sha256Xattr {
			rww.contentHash = sha256.New()
		}
	} else {
		// Avoid writing error messages and such to disk
		err := rww.file.Cleanup()
		if err != nil {
			rww.logger.Error("failed to clean up mirror file",
				zap.Error(err))
		}
	}
	rww.ResponseWriter.WriteHeader(statusCode)
}

func createTempFile(path string) (*renameio.PendingFile, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, mkdirPerms); err != nil {
		return nil, &fs.PathError{
			Op:   "createTempFile",
			Path: path,
			Err:  err,
		}
	}
	stat, err := os.Lstat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, &fs.PathError{
			Op:   "createTempFile",
			Path: path,
			Err:  err,
		}
	}
	if stat != nil && !stat.Mode().IsRegular() {
		return nil, &fs.PathError{
			Op:   "createTempFile",
			Path: path,
			Err:  ErrNotRegular,
		}
	}

	// Create a temporary file in the same directory as the destination named ".<name><random numbers>"
	temp, err := renameio.TempFile(dir, path)
	if err != nil {
		return nil, &fs.PathError{
			Op:   "createTempFile",
			Path: path,
			Err:  err,
		}
	}
	if stat != nil {
		// Attempt to chmod the temporary file to match the destination
		ts, err := temp.Stat()
		if err != nil {
			closeErr := temp.Cleanup()
			return nil, &fs.PathError{
				Op:   "createTempFile",
				Path: path,
				Err:  errors.Join(err, closeErr),
			}
		}
		if ts.Mode().Perm() != stat.Mode().Perm() {
			err := temp.Chmod(stat.Mode().Perm())
			if err != nil {
				closeErr := temp.Cleanup()
				return nil, &fs.PathError{
					Op:   "createTempFile",
					Path: path,
					Err:  errors.Join(err, closeErr),
				}
			}
		}
	}
	return temp, nil
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
