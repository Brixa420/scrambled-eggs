"""
Run a simple test of the ModelRegistry.
"""
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent)
sys.path.insert(0, project_root)

def run_test():
    try:
        print("Testing ModelRegistry...")
        from brixa.ai.registry.registry import ModelRegistry
        
        print("Creating test directory...")
        test_dir = Path("./test_models")
        test_dir.mkdir(exist_ok=True)
        
        print("Creating ModelRegistry instance...")
        registry = ModelRegistry(storage_root=str(test_dir))
        
        print("Registering test model...")
        success = registry.register_model(
            name="test_model",
            version="1.0.0",
            framework="pytorch",
            description="Test model"
        )
        
        if success:
            print("✅ Test passed! Model registered successfully.")
            print(f"Registered models: {list(registry.version_managers.keys())}")
            return 0
        else:
            print("❌ Test failed: Failed to register model")
            return 1
            
    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Cleanup
        import shutil
        if test_dir.exists():
            shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(run_test())
