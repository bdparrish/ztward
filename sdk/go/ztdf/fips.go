package ztdf

import (
	"github.com/bdparrish/ztward/sdk/go/internal/fipsruntime"
)

func isFIPSModeEnabled() bool {
	return fipsruntime.Enabled()
}
