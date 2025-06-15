package hooks

import (
	"fmt"
	"sync"

	"github.com/juicycleff/frank/pkg/logging"
)

// HookPlugin Plugin system for hooks
type HookPlugin interface {
	Name() string
	Version() string
	Initialize(registry HookRegistry) error
	Shutdown() error
	Health() error
}

type PluginManager struct {
	plugins map[string]HookPlugin
	mutex   sync.RWMutex
	logger  logging.Logger
}

func NewPluginManager(logger logging.Logger) *PluginManager {
	return &PluginManager{
		plugins: make(map[string]HookPlugin),
		logger:  logger,
	}
}

func (pm *PluginManager) Register(plugin HookPlugin) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	name := plugin.Name()
	if _, exists := pm.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	pm.plugins[name] = plugin
	pm.logger.Info("Plugin registered",
		logging.String("name", name),
		logging.String("version", plugin.Version()),
	)

	return nil
}

func (pm *PluginManager) Unregister(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	plugin, exists := pm.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	if err := plugin.Shutdown(); err != nil {
		pm.logger.Error("Failed to shutdown plugin",
			logging.String("name", name),
			logging.Error(err),
		)
	}

	delete(pm.plugins, name)
	pm.logger.Info("Plugin unregistered", logging.String("name", name))

	return nil
}

func (pm *PluginManager) Initialize(registry HookRegistry) error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	for name, plugin := range pm.plugins {
		if err := plugin.Initialize(registry); err != nil {
			pm.logger.Error("Failed to initialize plugin",
				logging.String("name", name),
				logging.Error(err),
			)
			return err
		}
	}

	return nil
}

func (pm *PluginManager) Shutdown() error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	for name, plugin := range pm.plugins {
		if err := plugin.Shutdown(); err != nil {
			pm.logger.Error("Failed to shutdown plugin",
				logging.String("name", name),
				logging.Error(err),
			)
		}
	}

	return nil
}

func (pm *PluginManager) Health() map[string]error {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	health := make(map[string]error)
	for name, plugin := range pm.plugins {
		health[name] = plugin.Health()
	}

	return health
}
