package tailscale

import (
	"sync"
	"time"
)

var _ TimedAuthCacher = (*TimedAuthCache)(nil)

type TimedAuthCache struct {
	expiration map[string]time.Time
	access     map[string]bool
	mutex      sync.RWMutex
}

type TimedAuthCacher interface {
	Get(key string) (access bool, fresh bool, ok bool)
	Set(key string, value bool, ttl time.Duration)
}

func NewTimedAuthCache() *TimedAuthCache {
	return &TimedAuthCache{
		expiration: make(map[string]time.Time),
		access:     make(map[string]bool),
		mutex:      sync.RWMutex{},
	}
}

func (c *TimedAuthCache) Get(key string) (access bool, fresh bool, ok bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	authorized, ok := c.access[key]

	return authorized, c.expiration[key].After(time.Now()) && ok, ok
}

func (c *TimedAuthCache) Set(key string, value bool, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.access[key] = value
	c.expiration[key] = time.Now().Add(ttl)
}
