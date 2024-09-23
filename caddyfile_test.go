package mirror

import (
	"testing"
)

func TestValidate(t *testing.T) {
	mir := Mirror{
		UseXattr:    false,
		Sha256Xattr: true,
	}
	err := mir.Validate()
	if err == nil {
		t.Errorf("Expected error for UseXattr=%v, Sha256Xattr=%v", mir.UseXattr, mir.Sha256Xattr)
	}
}
