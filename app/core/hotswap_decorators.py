"""
Decorators for hot-swappable components.

This module provides decorators to make classes and functions hot-swappable,
allowing them to be updated while the application is running.
"""

import functools
import importlib
import inspect
import logging
import sys
import types
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union, cast

from .hotswap import hotswap_manager, HotSwapError

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

# Global registry for hot-swappable components
_hotswap_registry: Dict[str, Dict[str, Any]] = {
    'classes': {},
    'functions': {},
    'instances': {}
}

def hotswappable(
    version: str = "1.0.0",
    dependencies: Optional[List[str]] = None,
    preserve_state: bool = True,
    auto_reload: bool = True
):
    """Decorator to make a class or function hot-swappable.
    
    Args:
        version: Version string for the component
        dependencies: List of module names this component depends on
        preserve_state: Whether to preserve instance state during hot-swapping
        auto_reload: Whether to automatically reload the component when its file changes
    """
    def decorator(component: Union[Type, Callable]) -> Union[Type, Callable]:
        if inspect.isclass(component):
            return _make_class_hotswappable(component, version, dependencies, preserve_state, auto_reload)
        elif callable(component):
            return _make_function_hotswappable(component, version, dependencies, auto_reload)
        else:
            raise TypeError("@hotswappable can only be applied to classes and functions")
    return decorator

def _make_class_hotswappable(
    cls: Type[T],
    version: str,
    dependencies: Optional[List[str]],
    preserve_state: bool,
    auto_reload: bool
) -> Type[T]:
    """Make a class hot-swappable."""
    module_name = cls.__module__
    class_name = cls.__name__
    full_name = f"{module_name}.{class_name}"
    
    # Register the module for hot-swapping
    try:
        hotswap_manager.register_module(
            module_name=module_name,
            version=version,
            dependencies=dependencies
        )
    except Exception as e:
        logger.warning(f"Failed to register module {module_name} for hot-swapping: {e}")
    
    # Create a wrapper class that will delegate to the actual implementation
    class HotSwapWrapper(cls):  # type: ignore
        _hs_original_class = cls
        _hs_wrapper_class = None
        _hs_instances = []
        _hs_version = version
        _hs_preserve_state = preserve_state
        
        def __new__(cls, *args, **kwargs):
            # Get the current implementation of the class
            current_class = _get_current_implementation(full_name, cls._hs_original_class)
            
            # Create an instance of the current implementation
            instance = super().__new__(current_class)
            instance.__init__(*args, **kwargs)
            
            # Store a reference to track instances if state preservation is enabled
            if cls._hs_preserve_state:
                cls._hs_instances.append(instance)
            
            return instance
        
        @classmethod
        def _hs_update_instances(cls, old_class, new_class):
            """Update all instances of this class with the new implementation."""
            if not cls._hs_preserve_state:
                return
                
            for instance in cls._hs_instances:
                # Skip instances that have been garbage collected
                if not hasattr(instance, '__dict__'):
                    continue
                
                # Save the instance's state
                state = {}
                for key, value in instance.__dict__.items():
                    if not key.startswith('_'):
                        state[key] = value
                
                # Update the instance's class
                instance.__class__ = new_class
                
                # Restore the instance's state
                for key, value in state.items():
                    setattr(instance, key, value)
    
    # Set the wrapper class name and module
    HotSwapWrapper.__name__ = cls.__name__
    HotSwapWrapper.__module__ = cls.__module__
    HotSwapWrapper.__qualname__ = getattr(cls, '__qualname__', cls.__name__)
    HotSwapWrapper.__doc__ = cls.__doc__
    
    # Store the wrapper class in the registry
    _hotswap_registry['classes'][full_name] = {
        'wrapper': HotSwapWrapper,
        'version': version,
        'preserve_state': preserve_state,
        'instances': HotSwapWrapper._hs_instances
    }
    
    # Register a state handler for the module
    def state_handler(old_module, new_module):
        if not auto_reload:
            return
            
        # Get the new class from the module
        new_class = getattr(new_module, class_name, None)
        if new_class is None or not inspect.isclass(new_class):
            logger.warning(f"Could not find class {class_name} in reloaded module {module_name}")
            return
        
        # Update the wrapper class
        HotSwapWrapper._hs_original_class = new_class
        
        # Update existing instances
        HotSwapWrapper._hs_update_instances(cls, new_class)
        
        logger.info(f"Updated class {full_name} to version {version}")
    
    # Register the state handler
    hotswap_manager.register_state_handler(module_name, state_handler)
    
    return cast(Type[T], HotSwapWrapper)

def _make_function_hotswappable(
    func: F,
    version: str,
    dependencies: Optional[List[str]],
    auto_reload: bool
) -> F:
    """Make a function hot-swappable."""
    module_name = func.__module__
    func_name = func.__name__
    full_name = f"{module_name}.{func_name}"
    
    # Register the module for hot-swapping
    try:
        hotswap_manager.register_module(
            module_name=module_name,
            version=version,
            dependencies=dependencies
        )
    except Exception as e:
        logger.warning(f"Failed to register module {module_name} for hot-swapping: {e}")
    
    # Create a wrapper function that will delegate to the current implementation
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Get the current implementation of the function
        current_func = _get_current_implementation(full_name, func)
        
        # Call the current implementation
        return current_func(*args, **kwargs)
    
    # Store the wrapper function in the registry
    _hotswap_registry['functions'][full_name] = {
        'wrapper': wrapper,
        'original': func,
        'version': version
    }
    
    # Register a state handler for the module
    def state_handler(old_module, new_module):
        if not auto_reload:
            return
            
        # Get the new function from the module
        new_func = getattr(new_module, func_name, None)
        if new_func is None or not callable(new_func):
            logger.warning(f"Could not find function {func_name} in reloaded module {module_name}")
            return
        
        # Update the wrapper function
        wrapper.__code__ = new_func.__code__
        wrapper.__defaults__ = getattr(new_func, '__defaults__', None)
        wrapper.__kwdefaults__ = getattr(new_func, '__kwdefaults__', None)
        wrapper.__annotations__ = getattr(new_func, '__annotations__', {})
        wrapper.__doc__ = new_func.__doc__
        
        logger.info(f"Updated function {full_name} to version {version}")
    
    # Register the state handler
    hotswap_manager.register_state_handler(module_name, state_handler)
    
    return cast(F, wrapper)

def _get_current_implementation(full_name: str, default: T) -> T:
    """Get the current implementation of a hot-swappable component."""
    if '.' not in full_name:
        return default
    
    module_name, name = full_name.rsplit('.', 1)
    
    try:
        # Get the current module
        module = sys.modules.get(module_name)
        if module is None:
            module = importlib.import_module(module_name)
        
        # Get the current implementation
        current = getattr(module, name, None)
        if current is not None:
            return current
    except Exception as e:
        logger.warning(f"Failed to get current implementation of {full_name}: {e}")
    
    return default

def get_hotswap_component(full_name: str) -> Any:
    """Get a hot-swappable component by its full name."""
    # Check if it's a registered class
    if full_name in _hotswap_registry['classes']:
        return _hotswap_registry['classes'][full_name]['wrapper']
    
    # Check if it's a registered function
    if full_name in _hotswap_registry['functions']:
        return _hotswap_registry['functions'][full_name]['wrapper']
    
    # Try to import the component
    if '.' in full_name:
        module_name, name = full_name.rsplit('.', 1)
        try:
            module = importlib.import_module(module_name)
            return getattr(module, name, None)
        except ImportError:
            pass
    
    return None
