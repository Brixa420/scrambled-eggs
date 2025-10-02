from dataclasses import dataclass, field
from typing import Dict, List, Type, TypeVar, Any, Set
import uuid

T = TypeVar('T')

class Component:
    """Base class for all components."""
    pass

@dataclass
class Entity:
    """An entity that can have multiple components."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    components: Dict[Type[Component], Component] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    def add_component(self, component: Component) -> 'Entity':
        """Add a component to the entity."""
        self.components[type(component)] = component
        return self
    
    def get_component(self, component_type: Type[T]) -> T:
        """Get a component by type."""
        return self.components.get(component_type)
    
    def has_component(self, component_type: Type[Component]) -> bool:
        """Check if entity has a specific component."""
        return component_type in self.components
    
    def remove_component(self, component_type: Type[Component]) -> None:
        """Remove a component from the entity."""
        self.components.pop(component_type, None)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the entity."""
        self.tags.add(tag)
    
    def has_tag(self, tag: str) -> bool:
        """Check if entity has a specific tag."""
        return tag in self.tags
    
    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the entity."""
        self.tags.discard(tag)

class System:
    """Base class for all systems."""
    def update(self, dt: float) -> None:
        """Update the system."""
        pass
    
    def draw(self, screen) -> None:
        """Draw the system's entities."""
        pass
    
    def handle_event(self, event) -> None:
        """Handle an event."""
        pass

class World:
    """Manages entities and systems."""
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.systems: List[System] = []
        self.entity_tags: Dict[str, Set[str]] = {}
    
    def create_entity(self) -> Entity:
        """Create a new entity."""
        entity = Entity()
        self.entities[entity.id] = entity
        return entity
    
    def remove_entity(self, entity_id: str) -> None:
        """Remove an entity by ID."""
        entity = self.entities.pop(entity_id, None)
        if entity:
            # Remove from tag index
            for tag in entity.tags:
                if tag in self.entity_tags:
                    self.entity_tags[tag].discard(entity_id)
    
    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get an entity by ID."""
        return self.entities.get(entity_id)
    
    def get_entities_with_component(self, component_type: Type[Component]) -> List[Entity]:
        """Get all entities with a specific component."""
        return [e for e in self.entities.values() if e.has_component(component_type)]
    
    def get_entities_with_tag(self, tag: str) -> List[Entity]:
        """Get all entities with a specific tag."""
        return [self.entities[eid] for eid in self.entity_tags.get(tag, set()) if eid in self.entities]
    
    def add_system(self, system: System) -> None:
        """Add a system to the world."""
        self.systems.append(system)
    
    def update(self, dt: float) -> None:
        """Update all systems."""
        for system in self.systems:
            system.update(dt)
    
    def draw(self, screen) -> None:
        """Draw all systems."""
        for system in self.systems:
            if hasattr(system, 'draw'):
                system.draw(screen)
    
    def handle_event(self, event) -> None:
        """Handle an event in all systems."""
        for system in self.systems:
            if hasattr(system, 'handle_event'):
                system.handle_event(event)
