import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import the Base class and settings
from app.db.base import Base
from app.core.config import settings

# Import all models to ensure they are registered with SQLAlchemy
from app.db import models  # noqa

# This is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Set the SQLAlchemy URL from settings
config.set_main_option('sqlalchemy.url', settings.DATABASE_URL)

# Target metadata for migrations
target_metadata = Base.metadata
{{ ... }}
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()

{{ ... }}
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
