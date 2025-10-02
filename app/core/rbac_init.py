""
RBAC initialization module.

This module provides functions to initialize the RBAC system with default roles and permissions.
"""
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.services.rbac_service import RBACService

def init_rbac() -> None:
    """Initialize the RBAC system with default roles and permissions."""
    db = SessionLocal()
    try:
        rbac_service = RBACService(db)
        rbac_service.ensure_default_roles_exist()
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def check_rbac_initialized(db: Session) -> bool:
    """Check if the RBAC system has been initialized."""
    from app.models.role import Role
    return db.query(Role).count() > 0
