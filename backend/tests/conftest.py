import os
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-with-at-least-32-characters"
