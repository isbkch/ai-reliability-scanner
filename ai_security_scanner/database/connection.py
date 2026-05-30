"""Database connection and session management."""

import logging
import os
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from ai_security_scanner.core.config import DatabaseConfig

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self, config: DatabaseConfig):
        """Initialize database manager.

        Args:
            config: Database configuration
        """
        self.config = config
        self._engine: Optional[Engine] = None
        self._session_factory: Optional[sessionmaker] = None

    def get_connection_url(self) -> str:
        """Build database connection URL.

        Returns:
            PostgreSQL connection URL
        """
        password = os.getenv(self.config.password_env, "")

        return (
            f"postgresql://{self.config.username}:{password}"
            f"@{self.config.host}:{self.config.port}/{self.config.database}"
        )

    def create_engine(self, echo: bool = False, pool_pre_ping: bool = True) -> Engine:
        """Create SQLAlchemy engine.

        Args:
            echo: Whether to echo SQL statements
            pool_pre_ping: Enable connection health checks

        Returns:
            SQLAlchemy engine instance
        """
        if self._engine is not None:
            return self._engine

        connection_url = self.get_connection_url()

        # Determine if we should use connection pooling
        use_pool = self.config.pool_size > 0

        engine_kwargs = {
            "echo": echo,
            "pool_pre_ping": pool_pre_ping,
            "connect_args": {
                "sslmode": self.config.ssl_mode,
                "connect_timeout": self.config.pool_timeout,
            },
        }

        if use_pool:
            engine_kwargs.update(
                {
                    "poolclass": QueuePool,
                    "pool_size": self.config.pool_size,
                    "max_overflow": self.config.max_overflow,
                    "pool_timeout": self.config.pool_timeout,
                }
            )
        else:
            engine_kwargs["poolclass"] = NullPool

        self._engine = create_engine(connection_url, **engine_kwargs)

        try:
            # Set up event listeners for connection management.
            @event.listens_for(self._engine, "connect")
            def receive_connect(dbapi_conn, connection_record):
                """Handle new database connections."""
                logger.debug("New database connection established")

            @event.listens_for(self._engine, "close")
            def receive_close(dbapi_conn, connection_record):
                """Handle database connection closure."""
                logger.debug("Database connection closed")

        except InvalidRequestError:
            logger.debug("Skipping database event listeners for non-SQLAlchemy engine")

        logger.info(
            f"Database engine created: {self.config.host}:{self.config.port}/{self.config.database}"
        )

        return self._engine

    def create_session_factory(self) -> sessionmaker:
        """Create session factory.

        Returns:
            SQLAlchemy session factory
        """
        if self._session_factory is not None:
            return self._session_factory

        if self._engine is None:
            self.create_engine()

        self._session_factory = sessionmaker(
            bind=self._engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )

        logger.debug("Session factory created")
        return self._session_factory

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Provide a transactional scope for database operations.

        Yields:
            Database session

        Example:
            with db_manager.session_scope() as session:
                session.add(scan_record)
                session.commit()
        """
        if self._session_factory is None:
            self.create_session_factory()

        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    def get_session(self) -> Session:
        """Get a new database session.

        Returns:
            Database session

        Note:
            Caller is responsible for closing the session.
            Consider using session_scope() context manager instead.
        """
        if self._session_factory is None:
            self.create_session_factory()

        return self._session_factory()

    def test_connection(self) -> bool:
        """Test database connection.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self._engine is None:
                self.create_engine()

            with self._engine.connect() as conn:
                conn.execute("SELECT 1")

            logger.info("Database connection test successful")
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False

    def dispose(self) -> None:
        """Dispose of the database engine and close all connections."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database engine disposed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.dispose()


def create_database_manager(config: Optional[DatabaseConfig] = None) -> DatabaseManager:
    """Create database manager instance.

    Args:
        config: Database configuration (uses default if None)

    Returns:
        DatabaseManager instance
    """
    if config is None:
        from ai_security_scanner.core.config import Config

        config = Config().database

    return DatabaseManager(config)
