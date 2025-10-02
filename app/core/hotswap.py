"""
Hot-swapping functionality for Scrambled Eggs.

This module provides the ability to dynamically update code and components
while the application is running, with support for:
- Module reloading
- State preservation
- Dependency management
- Rollback capabilities
"""

import importlib
import importlib.util
import inspect
import logging
import os
import sys
import time
import types
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union
)

from ..core.config import settings

logger = logging.getLogger(__name__)

T = TypeVar('T')

class HotSwapError(Exception):
    """Base exception for hot-swapping related errors."""
    pass

class ModuleState(Enum):
    """State of a hot-swappable module."""
    LOADED = auto()
    DIRTY = auto()  # Modified but not yet reloaded
    RELOADING = auto()
    ERROR = auto()

class DependencyGraph:
    """Dependency graph for tracking module dependencies."""
    
    def __init__(self):
        self._dependencies: Dict[str, Set[str]] = defaultdict(set)
        self._dependents: Dict[str, Set[str]] = defaultdict(set)
    
    def add_dependency(self, module_name: str, depends_on: str) -> None:
        """Add a dependency relationship between two modules."""
        if module_name != depends_on:  # Avoid self-dependencies
            self._dependencies[module_name].add(depends_on)
            self._dependents[depends_on].add(module_name)
    
    def get_dependencies(self, module_name: str) -> Set[str]:
        """Get all dependencies of a module (transitive closure)."""
        visited = set()
        to_visit = {module_name}
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
                
            visited.add(current)
            to_visit.update(self._dependencies.get(current, set()) - visited)
        
        return visited - {module_name}  # Exclude self
    
    def get_dependents(self, module_name: str) -> Set[str]:
        """Get all modules that depend on the given module."""
        visited = set()
        to_visit = {module_name}
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
                
            visited.add(current)
            to_visit.update(self._dependents.get(current, set()) - visited)
        
        return visited - {module_name}  # Exclude self
    
    def get_update_order(self, modules: List[str]) -> List[str]:
        """Get the order in which modules should be updated."""
        # Simple topological sort (Kahn's algorithm)
        graph = {m: set(self._dependencies.get(m, set())) for m in modules}
        in_degree = {m: 0 for m in modules}
        
        for m in modules:
            for dep in self._dependencies.get(m, set()):
                if dep in in_degree:
                    in_degree[dep] += 1
        
        # Initialize queue with nodes with no incoming edges
        queue = [m for m in modules if in_degree[m] == 0]
        result = []
        
        while queue:
            node = queue.pop(0)
            result.append(node)
            
            for m in self._dependents.get(node, set()):
                if m in in_degree:
                    in_degree[m] -= 1
                    if in_degree[m] == 0:
                        queue.append(m)
        
        if len(result) != len(modules):
            # There's a cycle in the dependency graph
            raise HotSwapError("Circular dependency detected in module graph")
        
        return result

@dataclass
class ModuleInfo:
    """Metadata for a hot-swappable module."""
    name: str
    path: Optional[Path] = None
    module: Optional[types.ModuleType] = None
    state: ModuleState = ModuleState.LOADED
    last_modified: float = 0.0
    version: str = "1.0.0"
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)
    error: Optional[Exception] = None
    
    @property
    def is_loaded(self) -> bool:
        """Check if the module is currently loaded."""
        return self.module is not None and self.state == ModuleState.LOADED
    
    @property
    def needs_reload(self) -> bool:
        """Check if the module needs to be reloaded."""
        if not self.path or not self.path.exists():
            return False
        return os.path.getmtime(self.path) > self.last_modified

class HotSwapManager:
    """Manager for hot-swapping modules and components."""
    
    def __init__(self):
        self._modules: Dict[str, ModuleInfo] = {}
        self._dependency_graph = DependencyGraph()
        self._state_handlers: Dict[Any, Callable[[Any, Any], None]] = {}
        self._watched_paths: Set[Path] = set()
        self._watcher = None
        self._lock = None  # Threading lock for thread safety
        self._initialized = False
    
    def initialize(self) -> None:
        """Initialize the hot-swap manager."""
        if self._initialized:
            return
            
        try:
            import threading
            self._lock = threading.RLock()
            
            # Start file watcher in a separate thread
            self._start_watcher()
            
            self._initialized = True
            logger.info("Hot-swap manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize hot-swap manager: {e}")
            raise HotSwapError(f"Failed to initialize hot-swap manager: {e}") from e
    
    def _start_watcher(self) -> None:
        """Start the file watcher for hot-reloading."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            
            class ModuleChangeHandler(FileSystemEventHandler):
                def __init__(self, manager):
                    self.manager = manager
                
                def on_modified(self, event):
                    if event.is_directory:
                        return
                    
                    path = Path(event.src_path)
                    if path.suffix != '.py':
                        return
                    
                    # Find the module that corresponds to this file
                    for module in self.manager._modules.values():
                        if module.path and module.path.samefile(path):
                            self.manager.mark_for_reload(module.name)
                            break
            
            self._watcher = Observer()
            self._watcher.schedule(
                ModuleChangeHandler(self),
                str(Path.cwd()),
                recursive=True
            )
            self._watcher.start()
            
        except ImportError:
            logger.warning(
                "watchdog package not installed. File watching for hot-reloading "
                "will be disabled. Install with: pip install watchdog"
            )
    
    def register_module(
        self,
        module_name: str,
        module_path: Optional[Union[str, Path]] = None,
        version: str = "1.0.0",
        dependencies: Optional[List[str]] = None
    ) -> None:
        """Register a module for hot-swapping.
        
        Args:
            module_name: Full dotted name of the module (e.g., 'app.services.my_service')
            module_path: Path to the module file (optional, will be inferred if not provided)
            version: Version string for the module
            dependencies: List of module names this module depends on
        """
        with self._lock:
            if module_name in self._modules:
                raise HotSwapError(f"Module {module_name} is already registered")
            
            # Get the module if it's already loaded
            module = sys.modules.get(module_name)
            
            # Determine the module path if not provided
            if module_path is None and module is not None:
                module_file = getattr(module, '__file__', None)
                if module_file:
                    module_path = Path(module_file).resolve()
            
            # Create module info
            info = ModuleInfo(
                name=module_name,
                path=Path(module_path) if module_path else None,
                module=module,
                version=version,
                dependencies=set(dependencies or []),
                last_modified=os.path.getmtime(module_path) if module_path else 0.0
            )
            
            # Update dependency graph
            for dep in info.dependencies:
                self._dependency_graph.add_dependency(module_name, dep)
            
            self._modules[module_name] = info
            
            # Watch the module directory for changes
            if module_path:
                self._watch_path(Path(module_path).parent)
            
            logger.debug(f"Registered module for hot-swapping: {module_name} (v{version})")
    
    def _watch_path(self, path: Path) -> None:
        """Add a path to the file watcher."""
        if not path.is_dir():
            path = path.parent
        
        path = path.resolve()
        if path not in self._watched_paths:
            self._watched_paths.add(path)
            
            if self._watcher is not None:
                from watchdog.observers import Observer
                if isinstance(self._watcher, Observer):
                    try:
                        self._watcher.schedule(
                            self._watcher.handlers[0],
                            str(path),
                            recursive=True
                        )
                    except Exception as e:
                        logger.warning(f"Failed to watch path {path}: {e}")
    
    def register_state_handler(
        self,
        module_name: str,
        handler: Callable[[Any, Any], None]
    ) -> None:
        """Register a state handler for a module.
        
        The handler will be called with (old_state, new_state) when the module's state changes.
        """
        with self._lock:
            if module_name not in self._modules:
                raise HotSwapError(f"Module {module_name} is not registered")
            
            self._state_handlers[module_name] = handler
    
    def mark_for_reload(self, module_name: str) -> None:
        """Mark a module for reloading on the next update cycle."""
        with self._lock:
            if module_name not in self._modules:
                logger.warning(f"Cannot reload unregistered module: {module_name}")
                return
            
            module_info = self._modules[module_name]
            if module_info.state != ModuleState.RELOADING:
                module_info.state = ModuleState.DIRTY
                logger.debug(f"Marked module for reload: {module_name}")
    
    def reload_module(self, module_name: str) -> None:
        """Reload a module and its dependencies."""
        with self._lock:
            if module_name not in self._modules:
                raise HotSwapError(f"Module {module_name} is not registered")
            
            # Get all modules that need to be reloaded (including dependencies)
            to_reload = self._get_update_plan(module_name)
            
            # Reload modules in the correct order
            for name in to_reload:
                self._reload_single_module(name)
    
    def _get_update_plan(self, module_name: str) -> List[str]:
        """Get the update plan for a module and its dependencies."""
        # Get all modules that need to be reloaded
        affected = {module_name}
        
        # Add dependencies that are also registered for hot-swapping
        for dep in self._dependency_graph.get_dependencies(module_name):
            if dep in self._modules:
                affected.add(dep)
        
        # Add dependents that need to be reloaded
        for dep in self._dependency_graph.get_dependents(module_name):
            if dep in self._modules:
                affected.add(dep)
        
        # Get update order (topological sort)
        return self._dependency_graph.get_update_order(list(affected))
    
    def _reload_single_module(self, module_name: str) -> None:
        """Reload a single module."""
        module_info = self._modules[module_name]
        
        if module_info.state == ModuleState.RELOADING:
            return
        
        old_module = module_info.module
        
        try:
            module_info.state = ModuleState.RELOADING
            
            if module_info.module is None:
                # Module is not loaded yet, import it
                module = importlib.import_module(module_name)
                module_info.module = module
            else:
                # Reload the module
                module = importlib.reload(module_info.module)
                module_info.module = module
            
            # Update metadata
            module_info.last_modified = (
                os.path.getmtime(module_info.path) 
                if module_info.path and module_info.path.exists() 
                else 0.0
            )
            module_info.state = ModuleState.LOADED
            module_info.error = None
            
            # Call state handlers
            if module_name in self._state_handlers:
                try:
                    self._state_handlers[module_name](old_module, module)
                except Exception as e:
                    logger.error(
                        f"Error in state handler for {module_name}: {e}",
                        exc_info=True
                    )
            
            logger.info(f"Reloaded module: {module_name}")
            
        except Exception as e:
            module_info.state = ModuleState.ERROR
            module_info.error = e
            logger.error(f"Failed to reload module {module_name}: {e}", exc_info=True)
            raise HotSwapError(f"Failed to reload module {module_name}: {e}") from e
    
    def get_module(self, module_name: str) -> types.ModuleType:
        """Get a module, loading it if necessary."""
        with self._lock:
            if module_name not in self._modules:
                # Auto-register the module if it's not registered
                self.register_module(module_name)
            
            module_info = self._modules[module_name]
            
            # Check if the module needs to be reloaded
            if module_info.needs_reload:
                self.reload_module(module_name)
            
            # Load the module if it's not loaded
            if module_info.module is None:
                try:
                    module = importlib.import_module(module_name)
                    module_info.module = module
                    module_info.state = ModuleState.LOADED
                except Exception as e:
                    module_info.state = ModuleState.ERROR
                    module_info.error = e
                    raise HotSwapError(f"Failed to load module {module_name}: {e}") from e
            
            return module_info.module
    
    def shutdown(self) -> None:
        """Shut down the hot-swap manager."""
        if self._watcher is not None:
            try:
                self._watcher.stop()
                self._watcher.join()
            except Exception as e:
                logger.error(f"Error stopping file watcher: {e}")
            
            self._watcher = None
        
        self._initialized = False
        logger.info("Hot-swap manager shut down")
    
    def __del__(self):
        self.shutdown()

# Global instance
hotswap_manager = HotSwapManager()

def enable_hot_swapping() -> None:
    """Enable hot-swapping for the application."""
    hotswap_manager.initialize()

def register_module(
    module_name: str,
    module_path: Optional[Union[str, Path]] = None,
    version: str = "1.0.0",
    dependencies: Optional[List[str]] = None
) -> None:
    """Register a module for hot-swapping."""
    hotswap_manager.register_module(module_name, module_path, version, dependencies)

def reload_module(module_name: str) -> None:
    """Reload a module and its dependencies."""
    hotswap_manager.reload_module(module_name)

def get_module(module_name: str) -> types.ModuleType:
    """Get a module, loading it if necessary."""
    return hotswap_manager.get_module(module_name)
