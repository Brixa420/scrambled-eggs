import pygame
from typing import List, Optional
from ..core.ecs import Entity, World, System, Component
from ..core.game_engine import Scene, GameEngine

class Button(Component):
    """Component for clickable UI buttons."""
    def __init__(self, text: str, rect: pygame.Rect, action: callable, **kwargs):
        self.text = text
        self.rect = rect
        self.action = action
        self.hovered = False
        self.kwargs = kwargs
        self.normal_color = kwargs.get('normal_color', (100, 100, 200))
        self.hover_color = kwargs.get('hover_color', (150, 150, 250))
        self.text_color = kwargs.get('text_color', (255, 255, 255))
        self.font = pygame.font.Font(None, 36)

class UIRenderSystem(System):
    """System for rendering UI elements."""
    def __init__(self, world: World, screen: pygame.Surface):
        super().__init__()
        self.world = world
        self.screen = screen
        
    def draw(self, screen=None):
        screen = screen or self.screen
        
        # Draw buttons
        for entity in self.world.get_entities_with_component(Button):
            button = entity.get_component(Button)
            color = button.hover_color if button.hovered else button.normal_color
            
            # Draw button background
            pygame.draw.rect(screen, color, button.rect, border_radius=5)
            pygame.draw.rect(screen, (0, 0, 0), button.rect, 2, border_radius=5)
            
            # Draw button text
            text_surface = button.font.render(button.text, True, button.text_color)
            text_rect = text_surface.get_rect(center=button.rect.center)
            screen.blit(text_surface, text_rect)

class UISystem(System):
    """System for handling UI interactions."""
    def __init__(self, world: World):
        super().__init__()
        self.world = world
        self.hovered_button = None
    
    def handle_event(self, event):
        if event.type == pygame.MOUSEMOTION:
            self._handle_mouse_motion(event)
        elif event.type == pygame.MOUSEBUTTONDOWN:
            if event.button == 1:  # Left mouse button
                self._handle_click(event.pos)
    
    def _handle_mouse_motion(self, event):
        mouse_pos = pygame.mouse.get_pos()
        
        # Reset hover state for all buttons
        for entity in self.world.get_entities_with_component(Button):
            button = entity.get_component(Button)
            button.hovered = button.rect.collidepoint(mouse_pos)
    
    def _handle_click(self, pos):
        for entity in self.world.get_entities_with_component(Button):
            button = entity.get_component(Button)
            if button.rect.collidepoint(pos):
                button.action(**button.kwargs)

class MainMenuScene(Scene):
    """Main menu scene for the game."""
    def __init__(self, game: GameEngine):
        super().__init__(game)
        self.world = World()
        self.setup_ui()
    
    def setup_ui(self):
        # Add UI systems
        self.world.add_system(UISystem(self.world))
        self.world.add_system(UIRenderSystem(self.world, self.game.screen))
        
        # Screen dimensions
        screen_width, screen_height = self.game.screen.get_size()
        button_width, button_height = 200, 50
        button_x = (screen_width - button_width) // 2
        
        # Create buttons
        start_button = self.world.create_entity()
        start_button.add_component(Button(
            text="Start Game",
            rect=pygame.Rect(button_x, 200, button_width, button_height),
            action=self.start_game
        ))
        
        options_button = self.world.create_entity()
        options_button.add_component(Button(
            text="Options",
            rect=pygame.Rect(button_x, 270, button_width, button_height),
            action=self.show_options
        ))
        
        quit_button = self.world.create_entity()
        quit_button.add_component(Button(
            text="Quit",
            rect=pygame.Rect(button_x, 340, button_width, button_height),
            action=self.quit_game
        ))
    
    def start_game(self, **kwargs):
        print("Starting game...")
        # Here you would transition to the game scene
        # self.game.set_scene("game")
    
    def show_options(self, **kwargs):
        print("Showing options...")
        # Here you would transition to the options menu
        # self.game.set_scene("options")
    
    def quit_game(self, **kwargs):
        self.game.running = False
    
    def update(self, dt: float):
        self.world.update(dt)
    
    def draw(self, screen: pygame.Surface):
        # Draw background
        screen.fill((30, 30, 40))
        
        # Draw title
        title_font = pygame.font.Font(None, 74)
        title_surface = title_font.render("Scrambled Eggs", True, (255, 255, 255))
        title_rect = title_surface.get_rect(center=(screen.get_width() // 2, 100))
        screen.blit(title_surface, title_rect)
        
        # Draw UI
        self.world.draw(screen)
    
    def handle_event(self, event):
        self.world.handle_event(event)
