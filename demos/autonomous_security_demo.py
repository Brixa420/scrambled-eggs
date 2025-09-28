"""
Autonomous Security System Demo

This script demonstrates the autonomous security system in action, including:
1. Basic security monitoring
2. Threat detection and response
3. Dynamic encryption layering
4. AI-powered security decisions
"""
import time
import random
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_demo.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecurityDemo")

# Import our security components
from scrambled_eggs.security.gateway import SecurityGateway
from scrambled_eggs.security.monitor import BreachSeverity

def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80)

def simulate_threat(gateway: SecurityGateway, threat_type: str, confidence: float):
    """Simulate a security threat with dramatic responses."""
    print(f"\n{'🔴' * 5} SIMULATING {threat_type.upper()} THREAT (CONFIDENCE: {confidence:.1%}) {'🔴' * 5}")
    
    # Get current layer count before the threat
    initial_layers = len(gateway.encryption.layers)
    
    # Simulate the threat
    if threat_type.lower() == 'brute_force':
        simulate_brute_force_attack(gateway, attempts=10)
    elif threat_type.lower() == 'timing_attack':
        simulate_timing_attack(gateway)
    else:
        # Generic threat simulation
        print(f"🔍 Simulating {threat_type}...")
        time.sleep(1)
        
        # Log the attempt
        gateway.monitor.log_attempt(
            client_id=f"attacker_{random.randint(1000, 9999)}",
            success=False,
            metadata={
                'type': threat_type.lower(),
                'confidence': confidence,
                'simulated': True
            }
        )
    
    # Check for breach (will always trigger for demo purposes)
    print("\n🔍 Analyzing security perimeter...")
    time.sleep(1)
    
    # Always detect a breach in demo mode to show response
    print("🚨 CRITICAL BREACH DETECTED!")
    print("💥 Initiating autonomous defense protocols...")
    
    # Simulate AI assessment
    enhanced_confidence = min(1.0, confidence * 1.2)  # Slightly enhance for demo
    
    # Determine severity based on confidence
    if enhanced_confidence > 0.8:
        severity = "CRITICAL"
    elif enhanced_confidence > 0.6:
        severity = "HIGH"
    elif enhanced_confidence > 0.4:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    print(f"\n🤖 AI THREAT ASSESSMENT")
    print(f"   Type: {threat_type}")
    print(f"   Confidence: {enhanced_confidence:.1%}")
    print(f"   Severity: {severity}")
    print(f"   Description: Potential {threat_type.replace('_', ' ')} detected")
    
    # Handle the breach with dramatic effect
    print("\n🚀 DEPLOYING COUNTERMEASURES...")
    time.sleep(1)
    
    # Calculate how many layers to add (exponential based on confidence)
    base_layers = int(10 ** (enhanced_confidence * 3))  # 10-1000 layers
    layers_to_add = random.randint(base_layers // 2, base_layers + (base_layers // 2))
    
    # Add the layers
    if layers_to_add > 100:
        print(f"🔒 Adding {layers_to_add} new encryption layers...")
    
    for i in range(layers_to_add):
        gateway.encryption.add_random_layer()
        if layers_to_add > 100 and (i + 1) % 100 == 0:
            print(f"  - Added {i + 1}/{layers_to_add} layers...")
    
    # Show results
    new_layers = len(gateway.encryption.layers)
    layers_added = new_layers - initial_layers
    
    print(f"\n✅ DEFENSE COMPLETE")
    print(f"   Added {layers_added} new encryption layers")
    print(f"   Total layers: {new_layers}")
    
    # Add dramatic effect for high-threat scenarios
    if enhanced_confidence > 0.8:
        print("\n⚠️  WARNING: ELEVATED THREAT LEVEL DETECTED")
        print("   Activating emergency security protocols...")
        time.sleep(1)
        print("   Quantum encryption shields: ONLINE")
        time.sleep(0.5)
        print("   Neural firewall: ENGAGED")
        time.sleep(0.5)
        print("   Threat neutralization: COMPLETE\n")

def simulate_normal_traffic(gateway, num_requests=5):
    """Simulate normal network traffic patterns."""
    print("\n🚦 Simulating normal network traffic...")
    for i in range(num_requests):
        time.sleep(0.3)
        print(f"  - Normal request {i+1}/{num_requests} processed")
        gateway.monitor.log_activity("normal_traffic")

def simulate_brute_force_attack(gateway, attempts=10):
    """Simulate a brute force attack."""
    print(f"\n💥 Simulating brute force attack with {attempts} attempts...")
    client_id = "attacker_" + str(random.randint(1000, 9999))
    for i in range(attempts):
        time.sleep(0.2)
        gateway.monitor.log_attempt(
            client_id=client_id,
            success=False,  # Failed attempt
            metadata={
                'type': 'brute_force',
                'attempt': i + 1,
                'suspicious': i % 3 == 0  # Every 3rd attempt is more suspicious
            }
        )

def show_security_status(gateway, context: str):
    """Display current security status."""
    print(f"\n🛡️  SECURITY STATUS: {context}")
    print(f"   Current layers: {len(gateway.encryption.layers)}")
    print(f"   Security level: {gateway.security_level}/10")
    print(f"   Base algorithm: {gateway.encryption.base_algorithm}")
    print(f"   Key size: {gateway.encryption.base_key_size} bits")

def simulate_timing_attack(gateway, client_id="timing_attacker"):
    """Simulate a timing attack."""
    print(f"\n⏱️  Simulating timing attack from {client_id}...")
    for i in range(15):
        time.sleep(0.1)  # Simulate timing variations
        gateway.monitor.log_attempt(
            client_id=client_id,
            success=True,  # Timing attacks often use successful responses
            metadata={
                'type': 'timing_attack',
                'attempt': i + 1,
                'response_time': 100 + random.randint(0, 200)  # ms
            }
        )
def run_demo():
    """Run the autonomous security demo."""
    print_header("🔐 Autonomous Security System Demo")
    
    # Initialize the security gateway with ultra-secure settings
    print("🔐 Initializing security gateway...")
    gateway = SecurityGateway({
        'autonomous_mode': True,
        'self_learning': True,
        'max_layers': 10000,  # Very high maximum for emergency cases
        'base_key_size': 1024,  # Extremely strong base encryption
        'adaptive_security': True,
        'threat_response_level': 0.3  # Respond to even low-confidence threats
    })
    
    # Add initial 1000 encryption layers
    print("🔒 Adding initial 1000 encryption layers...")
    for i in range(1000):
        gateway.encryption.add_random_layer()
        if (i + 1) % 100 == 0:
            print(f"  - Added {i + 1}/1000 layers...")
    print("✅ Initial security setup complete!")
    print(f"🔐 Current encryption layers: {len(gateway.encryption.layers)}")
    
    # Simulate normal traffic
    input("\nPress Enter to simulate normal traffic...")
    simulate_normal_traffic(gateway, num_requests=5)
    show_security_status(gateway, "After Normal Traffic")
    
    # Simulate brute force attack
    input("\nPress Enter to simulate a brute force attack...")
    simulate_brute_force_attack(gateway, attempts=15)
    show_security_status(gateway, "After Brute Force Attack")
    
    # Simulate timing attack
    input("\nPress Enter to simulate a timing attack...")
    simulate_timing_attack(gateway)
    show_security_status(gateway, "After Timing Attack")
    
    # Simulate a high-confidence threat
    input("\nPress Enter to simulate a critical threat...")
    simulate_threat(gateway, "zero_day_exploit", 0.95)
    show_security_status(gateway, "After Critical Threat")
    
    print("\n" + "=" * 80)
    print(" DEMO COMPLETE ".center(80, "="))
    print("=" * 80)
    print("\n🔒 Final Security Status:")
    print(f"- Total encryption layers: {len(gateway.encryption.layers)}")
    print(f"- Base algorithm: {gateway.encryption.base_algorithm}")
    print(f"- Key size: {gateway.encryption.base_key_size} bits")
    print("\nThank you for testing the Autonomous Security System!")

if __name__ == "__main__":
    try:
        run_demo()
        print("\nDemo stopped by user.")
    except Exception as e:
        logger.error(f"Error in demo: {e}", exc_info=True)
        print(f"\n❌ An error occurred: {e}")
    finally:
        print("\nThank you for using the Autonomous Security System Demo!")
        print("Check 'security_demo.log' for detailed logs.")
