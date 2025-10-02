import pygame
import sys
from typing import Dict, List, Optional, Type, TypeVar, Generic, Any
from dataclasses import dataclass
import time

T = TypeVar('T')

@dataclass
class GameConfig:
    title: str = "Scrambled Eggs"
    width: int = 1280
    height: int = 720
    target_fps: int = 60
    vsync: bool = True
    debug: bool = True

class Scene:
    def __init__(self, game: 'GameEngine'):
        self.game = game
        self.entities = []
        self.systems = []
        self.active = False
    
    def start(self):
        self.active = True
        
    def stop(self):
        self.active = False
        
    def update(self, dt: float):
        for system in self.systems:
            system.update(dt)
    
    def draw(self, screen: pygame.Surface):
        for system in self.systems:
            if hasattr(system, 'draw'):
                system.draw(screen)

class GameEngine:
    def __init__(self, config: GameConfig = None):
        pygame.init()
        self.config = config or GameConfig()
        self.running = False
        self.clock = pygame.time.Clock()
        self.dt = 0
        self.last_time = time.time()
        
        # Set up the display
        flags = pygame.DOUBLEBUF | pygame.HWSURFACE
        if self.config.vsync:
            flags |= pygame.HWSURFACE | pygame.DOUBLEBUF
            
        self.screen = pygame.display.set_mode(
            (self.config.width, self.config.height),
            flags
        )
        pygame.display.set_caption(self.config.title)
        
        # Scene management
        self.scenes: Dict[str, Scene] = {}
        self.current_scene: Optional[Scene] = None
        
        # Asset management
        self.assets = {
            'images': {},
            'sounds': {},
            'fonts': {}
        }
    
    def add_scene(self, name: str, scene: Scene) -> None:
        """Add a new scene to the game."""
        self.scenes[name] = scene
        if not self.current_scene:
            self.set_scene(name)
    
    def set_scene(self, name: str) -> bool:
        """Switch to a different scene."""
        if name in self.scenes:
            if self.current_scene:
                self.current_scene.stop()
            self.current_scene = self.scenes[name]
            self.current_scene.start()
            return True
        return False
    
    def load_assets(self):
        """Load all game assets."""
        # This should be overridden by the game
        pass
    
    def handle_events(self):
        """Handle pygame events."""
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False
            
            # Pass events to the current scene
            if self.current_scene:
                for system in self.current_scene.systems:
                    if hasattr(system, 'handle_event'):
                        system.handle_event(event)
    
    def update(self):
        """Update game state."""
        current_time = time.time()
        self.dt = current_time - self.last_time
        self.last_time = current_time
        
        if self.current_scene:
            self.current_scene.update(self.dt)
    
    def draw(self):
        """Render the game."""
        self.screen.fill((0, 0, 0))  # Clear screen with black
        
        if self.current_scene:
            self.current_scene.draw(self.screen)
        
        pygame.display.flip()
    
    def run(self):
        """Run the main game loop."""
        self.running = True
        self.load_assets()
        
        # Main game loop
        while self.running:
            self.handle_events()
            self.update()
            self.draw()
            self.clock.tick(self.config.target_fps)
        
        self.cleanup()
    
    def cleanup(self):
        """Clean up resources."""
        pygame.quit()
        sys.exit()

# Example usage
if __name__ == "__main__":
    config = GameConfig(
        title="Scrambled Eggs",
        width=1280,
        height=720,
        target_fps=60,
        vsync=True,
        debug=True
    )
    
    game = GameEngine(config)
    game.run()
