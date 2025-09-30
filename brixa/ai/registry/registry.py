import os
import json
import shutil
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, TypeVar, Union
from dataclasses import dataclass, field, asdict
import hashlib
from datetime import datetime

from .versioning import VersionManager, VersionStatus, VersionInfo

class ModelRegistry:
    def __init__(self, storage_root: str = "model_registry"):
        self.storage_root = Path(storage_root)
        self.registry_file = self.storage_root / "registry.json"
        self.version_managers: Dict[str, VersionManager] = {}
        self._load_registry()

    def _load_registry(self):
        """Load the registry from disk."""
        if not self.registry_file.exists():
            return

        with open(self.registry_file, 'r') as f:
            data = json.load(f)
            for model_name, versions in data.items():
                vm = VersionManager()
                for version, vdata in versions.items():
                    vm.create_version(
                        version=version,
                        framework=vdata['framework'],
                        description=vdata.get('description', ''),
                        metadata=vdata.get('metadata', {}),
                        parent_version=vdata.get('parent_version')
                    )
                    if 'status' in vdata:
                        vm.promote_version(version, VersionStatus[vdata['status']])
                self.version_managers[model_name] = vm

    def _save_registry(self):
        """Save the registry to disk."""
        data = {}
        for model_name, vm in self.version_managers.items():
            data[model_name] = {}
            for version, version_info in vm.versions.items():
                data[model_name][version] = {
                    'framework': version_info.framework,
                    'status': version_info.status.name,
                    'description': version_info.description,
                    'metadata': version_info.metadata,
                    'parent_version': version_info.parent_version,
                    'created_at': version_info.created_at.isoformat(),
                    'updated_at': version_info.updated_at.isoformat()
                }
        
        # Ensure directory exists
        self.storage_root.mkdir(parents=True, exist_ok=True)
        
        with open(self.registry_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def register_model(self, name: str, version: str, framework: str, **kwargs) -> bool:
        """Register a new model version."""
        if name not in self.version_managers:
            self.version_managers[name] = VersionManager()
        
        vm = self.version_managers[name]
        
        try:
            version_info = vm.create_version(
                version=version,
                framework=framework,
                description=kwargs.get('description', ''),
                metadata=kwargs.get('metadata', {}),
                parent_version=kwargs.get('parent_version')
            )
            
            # Create model directory
            model_dir = self._get_model_dir(name, version)
            model_dir.mkdir(parents=True, exist_ok=True)
            
            # Save metadata
            self._save_registry()
            return True
        except ValueError:
            return False

    def save_model(self, name: str, version: str, model: Any, **kwargs) -> bool:
        """Save a model to the registry."""
        model_dir = self.get_model_path(name, version)
        if not model_dir:
            return False

        try:
            version_info = self.version_managers[name].get_version(version)
            framework = version_info.framework.lower()
            
            if framework == 'pytorch':
                import torch
                if hasattr(model, 'save_pretrained'):  # HuggingFace
                    model.save_pretrained(str(model_dir))
                else:  # Standard PyTorch
                    torch.save({
                        'model_state_dict': model.state_dict(),
                        'model_class': model.__class__.__name__,
                        'model_module': model.__class__.__module__
                    }, model_dir / 'model.pt')
                    
            elif framework == 'tensorflow':
                import tensorflow as tf
                if hasattr(model, 'save_pretrained'):  # HuggingFace
                    model.save_pretrained(str(model_dir))
                else:  # Keras
                    tf.keras.models.save_model(model, str(model_dir))
                    
            elif framework in ['sklearn', 'scikit-learn']:
                import joblib
                joblib.dump(model, model_dir / 'model.joblib')
                
            else:
                raise ValueError(f"Unsupported framework: {framework}")
                
            return True
            
        except Exception as e:
            raise RuntimeError(f"Failed to save {framework} model: {str(e)}")

    def load_model(self, name: str, version: str, **kwargs) -> Any:
        """Load a model from the registry."""
        model_dir = self.get_model_path(name, version)
        if not model_dir:
            return None

        version_info = self.version_managers[name].get_version(version)
        if not version_info:
            return None

        try:
            framework = version_info.framework.lower()
            
            if framework == 'pytorch':
                import torch
                model_path = model_dir / 'model.pt'
                if model_path.exists():  # Standard PyTorch
                    checkpoint = torch.load(model_path, **kwargs)
                    module = importlib.import_module(checkpoint['model_module'])
                    model_class = getattr(module, checkpoint['model_class'])
                    model = model_class()
                    model.load_state_dict(checkpoint['model_state_dict'])
                    return model
                else:  # HuggingFace
                    from transformers import AutoModel
                    return AutoModel.from_pretrained(str(model_dir), **kwargs)
                    
            elif framework == 'tensorflow':
                import tensorflow as tf
                if (model_dir / 'tf_model.h5').exists() or (model_dir / 'saved_model.pb').exists():
                    return tf.keras.models.load_model(str(model_dir), **kwargs)
                else:  # HuggingFace
                    from transformers import TFAutoModel
                    return TFAutoModel.from_pretrained(str(model_dir), **kwargs)
                    
            elif framework in ['sklearn', 'scikit-learn']:
                import joblib
                return joblib.load(model_dir / 'model.joblib')
                
            else:
                raise ValueError(f"Unsupported framework: {framework}")
                
        except Exception as e:
            raise RuntimeError(f"Failed to load {framework} model: {str(e)}")

    # Helper methods
    def _get_model_dir(self, name: str, version: str) -> Path:
        """Get the directory path for a model version."""
        return self.storage_root / name.replace(' ', '_') / version

    def get_model_path(self, name: str, version: str) -> Optional[Path]:
        """Get the filesystem path for a model version."""
        if name not in self.version_managers:
            return None
        if not self.version_managers[name].get_version(version):
            return None
        return self._get_model_dir(name, version)

    def list_models(self) -> List[str]:
        """List all registered models."""
        return list(self.version_managers.keys())

    def list_versions(self, name: str, status: Optional[VersionStatus] = None) -> List[VersionInfo]:
        """List all versions of a model, optionally filtered by status."""
        if name not in self.version_managers:
            return []
        return self.version_managers[name].list_versions(status)

    def promote_version(self, name: str, version: str, target_status: VersionStatus) -> bool:
        """Promote a model version to a new status."""
        if name not in self.version_managers:
            return False
        success = self.version_managers[name].promote_version(version, target_status)
        if success:
            self._save_registry()
        return success

    def get_version_lineage(self, name: str, version: str) -> List[VersionInfo]:
        """Get the lineage of a model version."""
        if name not in self.version_managers:
            return []
        return self.version_managers[name].get_version_lineage(version)

    def rollback_version(self, name: str, version: str, new_version: str) -> bool:
        """Rollback to a previous version of a model.
        
        Args:
            name: Name of the model
            version: Version to rollback to
            new_version: New version number for the rollback
            
        Returns:
            bool: True if rollback was successful, False otherwise
        """
        if name not in self.version_managers:
            return False
            
        vm = self.version_managers[name]
        versions = [v.version for v in vm.list_versions()]
        if version not in versions:
            return False
            
        # Create a new version based on the rollback target
        version_info = vm.get_version(version)
        if not version_info:
            return False
            
        # Create new version with the same metadata as the target version
        success = self.register_model(
            name=name,
            version=new_version,
            framework=version_info.framework,
            description=f"Rollback to version {version}",
            metadata=version_info.metadata,
            parent_version=version
        )
        
        if not success:
            return False
            
        # Copy model files if they exist
        src_dir = self._get_model_dir(name, version)
        dst_dir = self._get_model_dir(name, new_version)
        
        if src_dir.exists() and not dst_dir.exists():
            shutil.copytree(src_dir, dst_dir)
            
        self._save_registry()
        return True

    def deprecate_version(self, name: str, version: str) -> bool:
        """Mark a model version as deprecated."""
        return self.promote_version(name, version, VersionStatus.DEPRECATED)

    def archive_version(self, name: str, version: str) -> bool:
        """Archive a model version."""
        return self.promote_version(name, version, VersionStatus.ARCHIVED)
