package hooks

import (
	"sync"
	"time"
)

// HookMetrics tracks hook execution metrics
type HookMetrics struct {
	mutex             sync.RWMutex
	executionCounts   map[HookType]int64
	successCounts     map[HookType]int64
	failureCounts     map[HookType]int64
	executionTimes    map[HookType][]time.Duration
	lastExecutionTime map[HookType]time.Time
}

func NewHookMetrics() *HookMetrics {
	return &HookMetrics{
		executionCounts:   make(map[HookType]int64),
		successCounts:     make(map[HookType]int64),
		failureCounts:     make(map[HookType]int64),
		executionTimes:    make(map[HookType][]time.Duration),
		lastExecutionTime: make(map[HookType]time.Time),
	}
}

func (hm *HookMetrics) RecordExecution(hookType HookType, success bool, duration time.Duration, hookCount int) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	hm.executionCounts[hookType]++
	hm.lastExecutionTime[hookType] = time.Now()

	if success {
		hm.successCounts[hookType]++
	} else {
		hm.failureCounts[hookType]++
	}

	// Keep only last 100 execution times for each hook type
	if len(hm.executionTimes[hookType]) >= 100 {
		hm.executionTimes[hookType] = hm.executionTimes[hookType][1:]
	}
	hm.executionTimes[hookType] = append(hm.executionTimes[hookType], duration)
}

func (hm *HookMetrics) GetStats(hookType HookType) HookStats {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	stats := HookStats{
		HookType:       hookType,
		ExecutionCount: hm.executionCounts[hookType],
		SuccessCount:   hm.successCounts[hookType],
		FailureCount:   hm.failureCounts[hookType],
		LastExecution:  hm.lastExecutionTime[hookType],
	}

	if stats.ExecutionCount > 0 {
		stats.SuccessRate = float64(stats.SuccessCount) / float64(stats.ExecutionCount) * 100
	}

	// Calculate average execution time
	times := hm.executionTimes[hookType]
	if len(times) > 0 {
		var total time.Duration
		for _, t := range times {
			total += t
		}
		stats.AverageExecutionTime = total / time.Duration(len(times))
	}

	return stats
}
