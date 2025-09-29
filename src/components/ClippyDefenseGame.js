import React, { useState, useEffect, useRef } from 'react';
import { clippyAI } from '../services/ai/ClippyAIService';
import '../styles/ClippyDefenseGame.css';

const ClippyDefenseGame = () => {
  const [gameState, setGameState] = useState({
    health: 100,
    securityLevel: 1,
    activeThreats: [],
    defenseLayers: [],
    score: 0,
    gameActive: false,
    gameOver: false,
    messages: []
  });
  
  const gameAreaRef = useRef(null);
  const animationFrameRef = useRef(null);
  const threatIntervalRef = useRef(null);
  
  // Threat types with different behaviors and appearances
  const threatTypes = [
    { 
      id: 'basic', 
      name: 'Script Kiddie', 
      speed: 2, 
      health: 3, 
      damage: 5, 
      color: '#ff6b6b',
      frequency: 0.6,
      points: 10
    },
    { 
      id: 'hacker', 
      name: 'Black Hat Hacker', 
      speed: 3, 
      health: 5, 
      damage: 10, 
      color: '#ff0000',
      frequency: 0.3,
      points: 25
    },
    { 
      id: 'ai', 
      name: 'Rogue AI', 
      speed: 1.5, 
      health: 15, 
      damage: 15, 
      color: '#9c27b0',
      frequency: 0.1,
      points: 50
    }
  ];

  // Defense layers with different properties
  const defenseLayers = [
    { id: 'firewall', name: 'Firewall', strength: 10, color: '#4caf50' },
    { id: 'encryption', name: 'Encryption', strength: 20, color: '#2196f3' },
    { id: 'ai', name: 'AI Guardian', strength: 30, color: '#ff9800' },
    { id: 'quantum', name: 'Quantum Lock', strength: 50, color: '#e91e63' }
  ];

  // Start the game
  const startGame = () => {
    setGameState({
      health: 100,
      securityLevel: 1,
      activeThreats: [],
      defenseLayers: [defenseLayers[0]], // Start with basic firewall
      score: 0,
      gameActive: true,
      gameOver: false,
      messages: ['Game started! Defend the core!']
    });
    
    // Start threat generation
    threatIntervalRef.current = setInterval(generateThreat, 3000);
    
    // Start game loop
    gameLoop();
  };
  
  // Game loop
  const gameLoop = () => {
    if (!gameState.gameActive || gameState.gameOver) return;
    
    updateGameState();
    renderGame();
    
    animationFrameRef.current = requestAnimationFrame(gameLoop);
  };
  
  // Update game state
  const updateGameState = () => {
    setGameState(prevState => {
      // Move threats
      const updatedThreats = prevState.activeThreats
        .map(threat => {
          // Move threat toward center
          const angle = Math.atan2(
            gameAreaRef.current.clientHeight/2 - threat.y,
            gameAreaRef.current.clientWidth/2 - threat.x
          );
          
          const speed = threat.speed * (1 + prevState.securityLevel * 0.1);
          const newX = threat.x + Math.cos(angle) * speed;
          const newY = threat.y + Math.sin(angle) * speed;
          
          // Check if reached center
          const distanceToCenter = Math.sqrt(
            Math.pow(newX - gameAreaRef.current.clientWidth/2, 2) + 
            Math.pow(newY - gameAreaRef.current.clientHeight/2, 2)
          );
          
          if (distanceToCenter < 30) {
            // Reached center, damage the core
            const newHealth = prevState.health - threat.damage;
            
            if (newHealth <= 0) {
              // Game over
              clearInterval(threatIntervalRef.current);
              return { ...threat, reachedCore: true };
            }
            
            return { ...threat, reachedCore: true };
          }
          
          return { ...threat, x: newX, y: newY };
        })
        .filter(threat => !threat.reachedCore && threat.health > 0);
      
      // Check for game over
      const gameOver = prevState.health <= 0 || 
        (prevState.activeThreats.some(t => t.reachedCore) && prevState.health <= 0);
      
      // Calculate new score
      const newScore = prevState.score + 1;
      
      // Level up every 1000 points
      const newSecurityLevel = Math.floor(newScore / 1000) + 1;
      
      // Add new defense layers as player levels up
      const newDefenseLayers = [...prevState.defenseLayers];
      if (newSecurityLevel > prevState.securityLevel) {
        const newLayerIndex = Math.min(newSecurityLevel - 1, defenseLayers.length - 1);
        if (!newDefenseLayers.some(layer => layer.id === defenseLayers[newLayerIndex].id)) {
          newDefenseLayers.push(defenseLayers[newLayerIndex]);
          addGameMessage(`Security level up! New defense: ${defenseLayers[newLayerIndex].name}`);
        }
      }
      
      return {
        ...prevState,
        activeThreats: updatedThreats,
        health: Math.max(0, prevState.health - 
          (prevState.activeThreats.filter(t => t.reachedCore).reduce((sum, t) => sum + t.damage, 0))),
        score: newScore,
        securityLevel: newSecurityLevel,
        defenseLayers: newDefenseLayers,
        gameOver: gameOver,
        gameActive: !gameOver
      };
    });
  };
  
  // Render the game
  const renderGame = () => {
    if (!gameAreaRef.current) return;
    
    const ctx = gameAreaRef.current.getContext('2d');
    if (!ctx) return;
    
    // Clear canvas
    ctx.clearRect(0, 0, gameAreaRef.current.width, gameAreaRef.current.height);
    
    // Draw defense rings
    gameState.defenseLayers.forEach((layer, index) => {
      const radius = 150 - (index * 30);
      ctx.beginPath();
      ctx.arc(
        gameAreaRef.current.width/2, 
        gameAreaRef.current.height/2, 
        radius, 
        0, 
        Math.PI * 2
      );
      ctx.strokeStyle = layer.color;
      ctx.lineWidth = 3;
      ctx.stroke();
      
      // Draw layer name
      ctx.fillStyle = layer.color;
      ctx.font = '12px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(
        layer.name, 
        gameAreaRef.current.width/2, 
        gameAreaRef.current.height/2 - radius - 5
      );
    });
    
    // Draw core
    ctx.beginPath();
    ctx.arc(
      gameAreaRef.current.width/2, 
      gameAreaRef.current.height/2, 
      20, 
      0, 
      Math.PI * 2
    );
    ctx.fillStyle = '#ffeb3b';
    ctx.fill();
    
    // Draw Clippy
    ctx.font = '20px Arial';
    ctx.fillStyle = '#fff';
    ctx.textAlign = 'center';
    ctx.fillText('🛡️', gameAreaRef.current.width/2, gameAreaRef.current.height/2 + 5);
    
    // Draw threats
    gameState.activeThreats.forEach(threat => {
      // Draw threat
      ctx.beginPath();
      ctx.arc(threat.x, threat.y, 10, 0, Math.PI * 2);
      ctx.fillStyle = threat.color;
      ctx.fill();
      
      // Draw health bar
      const healthPercent = threat.health / threat.maxHealth;
      ctx.fillStyle = '#ff0000';
      ctx.fillRect(threat.x - 15, threat.y - 20, 30, 5);
      ctx.fillStyle = '#00ff00';
      ctx.fillRect(threat.x - 15, threat.y - 20, 30 * healthPercent, 5);
      
      // Draw threat name
      ctx.fillStyle = '#fff';
      ctx.font = '10px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(threat.name, threat.x, threat.y - 25);
    });
  };
  
  // Generate a new threat
  const generateThreat = () => {
    if (!gameState.gameActive || gameState.gameOver) return;
    
    // Choose random threat type based on frequency
    const rand = Math.random();
    let cumulativeProb = 0;
    let selectedThreat = null;
    
    for (const threat of threatTypes) {
      cumulativeProb += threat.frequency;
      if (rand < cumulativeProb) {
        selectedThreat = threat;
        break;
      }
    }
    
    if (!selectedThreat) selectedThreat = threatTypes[0]; // Fallback
    
    // Random position on edge of game area
    let x, y;
    if (Math.random() < 0.5) {
      x = Math.random() < 0.5 ? 0 : gameAreaRef.current.width;
      y = Math.random() * gameAreaRef.current.height;
    } else {
      x = Math.random() * gameAreaRef.current.width;
      y = Math.random() < 0.5 ? 0 : gameAreaRef.current.height;
    }
    
    const newThreat = {
      ...selectedThreat,
      x,
      y,
      maxHealth: selectedThreat.health,
      reachedCore: false
    };
    
    setGameState(prevState => ({
      ...prevState,
      activeThreats: [...prevState.activeThreats, newThreat]
    }));
    
    addGameMessage(`Incoming threat: ${selectedThreat.name} detected!`);
  };
  
  // Handle clicking on threats
  const handleCanvasClick = (e) => {
    if (!gameState.gameActive || gameState.gameOver) return;
    
    const rect = gameAreaRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    // Check if clicked on a threat
    const clickedThreat = gameState.activeThreats.find(threat => {
      const distance = Math.sqrt(
        Math.pow(threat.x - x, 2) + Math.pow(threat.y - y, 2)
      );
      return distance < 15; // Click radius
    });
    
    if (clickedThreat) {
      // Damage the threat
      const updatedThreats = gameState.activeThreats.map(threat => {
        if (threat === clickedThreat) {
          const newHealth = threat.health - 1;
          return { ...threat, health: newHealth };
        }
        return threat;
      }).filter(threat => threat.health > 0);
      
      // Add to score
      const pointsEarned = clickedThreat.points * gameState.securityLevel;
      
      setGameState(prevState => ({
        ...prevState,
        activeThreats: updatedThreats,
        score: prevState.score + pointsEarned
      }));
      
      addGameMessage(`Threat neutralized! +${pointsEarned} points`);
    }
  };
  
  // Add message to game log
  const addGameMessage = (message) => {
    setGameState(prevState => ({
      ...prevState,
      messages: [message, ...prevState.messages].slice(0, 10) // Keep last 10 messages
    }));
  };
  
  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
      if (threatIntervalRef.current) {
        clearInterval(threatIntervalRef.current);
      }
    };
  }, []);
  
  // Handle window resize
  useEffect(() => {
    const handleResize = () => {
      if (gameAreaRef.current) {
        gameAreaRef.current.width = gameAreaRef.current.offsetWidth;
        gameAreaRef.current.height = gameAreaRef.current.offsetHeight;
      }
    };
    
    window.addEventListener('resize', handleResize);
    handleResize(); // Initial size
    
    return () => window.removeEventListener('resize', handleResize);
  }, []);
  
  return (
    <div className="clippy-defense-game">
      <div className="game-header">
        <h1>Clippy's Security Defense</h1>
        <div className="game-stats">
          <div className="stat">
            <span className="stat-label">Health:</span>
            <div className="health-bar">
              <div 
                className="health-fill" 
                style={{ width: `${Math.max(0, gameState.health)}%` }}
              ></div>
              <span className="health-text">{Math.round(gameState.health)}%</span>
            </div>
          </div>
          <div className="stat">
            <span className="stat-label">Security Level:</span>
            <span className="stat-value">{gameState.securityLevel}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Score:</span>
            <span className="stat-value">{gameState.score}</span>
          </div>
        </div>
      </div>
      
      <div className="game-container">
        <div className="game-area-container">
          <canvas 
            ref={gameAreaRef} 
            className="game-area"
            onClick={handleCanvasClick}
          ></canvas>
          
          {!gameState.gameActive && !gameState.gameOver && (
            <div className="game-overlay">
              <h2>Clippy's Security Defense</h2>
              <p>Protect the core from incoming threats!</p>
              <button onClick={startGame} className="start-button">
                Start Game
              </button>
            </div>
          )}
          
          {gameState.gameOver && (
            <div className="game-overlay">
              <h2>Game Over!</h2>
              <p>Your final score: {gameState.score}</p>
              <p>Security Level Reached: {gameState.securityLevel}</p>
              <button onClick={startGame} className="start-button">
                Play Again
              </button>
            </div>
          )}
        </div>
        
        <div className="game-log">
          <h3>Security Log</h3>
          <div className="log-messages">
            {gameState.messages.map((msg, index) => (
              <div key={index} className="log-message">{msg}</div>
            ))}
            {gameState.messages.length === 0 && (
              <div className="log-message">No security events yet. Start the game!</div>
            )}
          </div>
          
          <div className="game-instructions">
            <h4>How to Play</h4>
            <ul>
              <li>Click on threats to eliminate them</li>
              <li>Prevent threats from reaching the core</li>
              <li>Earn points by defeating threats</li>
              <li>Level up to unlock new defenses</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div className="defense-info">
        <h3>Active Defenses</h3>
        <div className="defense-list">
          {gameState.defenseLayers.map((layer, index) => (
            <div key={layer.id} className="defense-item">
              <div 
                className="defense-color" 
                style={{ backgroundColor: layer.color }}
              ></div>
              <div className="defense-details">
                <div className="defense-name">{layer.name}</div>
                <div className="defense-strength">
                  Strength: {layer.strength}
                </div>
              </div>
            </div>
          ))}
          
          {defenseLayers
            .filter(layer => !gameState.defenseLayers.some(l => l.id === layer.id))
            .map(layer => (
              <div key={layer.id} className="defense-item locked">
                <div className="defense-color">🔒</div>
                <div className="defense-details">
                  <div className="defense-name">Locked</div>
                  <div className="defense-unlock">
                    Reach level {defenseLayers.findIndex(l => l.id === layer.id) + 1} to unlock
                  </div>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
};

export default ClippyDefenseGame;
