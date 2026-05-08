package common

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

const defaultMemoryLimitRatio = 65

func InitRuntimeTuning() {
	if os.Getenv("GOMAXPROCS") == "" {
		if n := containerCPUQuota(); n > 0 {
			runtime.GOMAXPROCS(n)
		}
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		if limit := containerMemoryLimit(); limit > 0 {
			debug.SetMemoryLimit(limit * defaultMemoryLimitRatio / 100)
		}
	}
}

func containerCPUQuota() int {
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) >= 2 && fields[0] != "max" {
			quota, qErr := strconv.ParseFloat(fields[0], 64)
			period, pErr := strconv.ParseFloat(fields[1], 64)
			if qErr == nil && pErr == nil && quota > 0 && period > 0 {
				return clampCPU(int(math.Ceil(quota / period)))
			}
		}
	}

	quota, qErr := readInt64File("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	period, pErr := readInt64File("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if qErr == nil && pErr == nil && quota > 0 && period > 0 {
		return clampCPU(int(math.Ceil(float64(quota) / float64(period))))
	}
	return 0
}

func clampCPU(n int) int {
	if n < 1 {
		return 1
	}
	if cpu := runtime.NumCPU(); cpu > 0 && n > cpu {
		return cpu
	}
	return n
}

func containerMemoryLimit() int64 {
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "max" {
			if limit, err := strconv.ParseInt(s, 10, 64); err == nil && validMemoryLimit(limit) {
				return limit
			}
		}
	}

	if limit, err := readInt64File("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil && validMemoryLimit(limit) {
		return limit
	}
	return 0
}

func validMemoryLimit(limit int64) bool {
	const minContainerMemory = 128 << 20
	return limit >= minContainerMemory && limit < math.MaxInt64/2
}

func readInt64File(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}
