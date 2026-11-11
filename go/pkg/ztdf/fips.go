package ztdf

import (
	"github.com/bdparrish/ztward/go/pkg/security/fipsruntime"
)

func isFIPSModeEnabled() bool {
	return fipsruntime.Enabled()
}
