package rate

import (
	"sync"
	"sync/atomic"
	"time"
)

type Rate struct {
	bucketSize        int64
	bucketSurplusSize int64
	bucketAddSize     int64
	doneChan          chan struct{}
	stopOnce          sync.Once
	NowRate           int64
}

func NewRate(addSize int64) *Rate {
	return &Rate{
		bucketSize:        addSize * 2,
		bucketSurplusSize: 0,
		bucketAddSize:     addSize,
		doneChan:          make(chan struct{}),
	}
}

func (s *Rate) Start() {
	go s.session()
}

func (s *Rate) add(size int64) {
	if res := s.bucketSize - s.bucketSurplusSize; res < s.bucketAddSize {
		atomic.AddInt64(&s.bucketSurplusSize, res)
		return
	}
	atomic.AddInt64(&s.bucketSurplusSize, size)
}

// 回桶
func (s *Rate) ReturnBucket(size int64) {
	s.add(size)
}

// 停止
func (s *Rate) Stop() {
	s.stopOnce.Do(func() {
		close(s.doneChan)
	})
}

func (s *Rate) Get(size int64) {
	if size <= 0 {
		return
	}
	if s.bucketSurplusSize >= size {
		atomic.AddInt64(&s.bucketSurplusSize, -size)
		return
	}
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.bucketSurplusSize >= size {
				atomic.AddInt64(&s.bucketSurplusSize, -size)
				return
			}
		case <-s.doneChan:
			return
		}
	}
}

func (s *Rate) session() {
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if rs := s.bucketAddSize - s.bucketSurplusSize; rs > 0 {
				s.NowRate = rs
			} else {
				s.NowRate = s.bucketSize - s.bucketSurplusSize
			}
			s.add(s.bucketAddSize)
		case <-s.doneChan:
			return
		}
	}
}
