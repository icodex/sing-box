package inbound

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	registry     adapter.InboundRegistry
	endpoint     adapter.EndpointManager
	access       sync.Mutex
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
	// scope and stage let a host create/remove inbounds after box startup
	// (xboard hot reload). Upstream 1.14.4 only registers inbounds in Create;
	// a created inbound would otherwise never run its lifecycle.
	scope   *adapter.Scope
	stage   adapter.StartStage
	started bool
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.scope = scope
	inbounds := m.inbounds
	m.access.Unlock()
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		err := scope.Start(name, inbound, stage)
		if err != nil {
			return err
		}
	}
	m.access.Lock()
	m.started = true
	if stage > m.stage {
		m.stage = stage
	}
	m.access.Unlock()
	return nil
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return m.inbounds
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	inbound, err := m.registry.Create(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	scope, started := m.scope, m.started
	replaced, loaded := m.inboundByTag[tag]
	if loaded {
		delete(m.inboundByTag, tag)
		for i, it := range m.inbounds {
			if it == replaced {
				m.inbounds = append(m.inbounds[:i], m.inbounds[i+1:]...)
				break
			}
		}
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	m.access.Unlock()

	if loaded && started && scope != nil {
		_ = scope.CloseChild(replaced)
	}
	if started && scope != nil {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			if err := scope.Start(name, inbound, stage); err != nil {
				return E.Cause(err, stage, " ", name)
			}
		}
	}
	return nil
}

// Remove detaches and closes one inbound. Returns os.ErrInvalid when the tag
// is unknown, matching the pre-1.14.4 manager contract.
func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.inboundByTag, tag)
	for i, it := range m.inbounds {
		if it == inbound {
			m.inbounds = append(m.inbounds[:i], m.inbounds[i+1:]...)
			break
		}
	}
	scope, started := m.scope, m.started
	m.access.Unlock()
	if started && scope != nil {
		return scope.CloseChild(inbound)
	}
	return nil
}

// Close stops accepting new connections for every inbound. It is used before
// the box's own Close so a restarted kernel can bind the same ports while
// in-flight connections drain in the background.
func (m *Manager) Close() error {
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	scope := m.scope
	inbounds := m.inbounds
	m.inbounds = nil
	m.inboundByTag = make(map[string]adapter.Inbound)
	m.access.Unlock()
	if scope == nil {
		return nil
	}
	var err error
	for _, inbound := range inbounds {
		err = errors.Join(err, scope.CloseChild(inbound))
	}
	return err
}
