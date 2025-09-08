import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Server Configuration - Use Render's PORT environment variable
    HOST: str = Field("0.0.0.0", description="Server host address")
    PORT: int = Field(default_factory=lambda: int(os.getenv("PORT", "8000")), description="Server port")
    
    # Session Management
    SESSION_TIMEOUT: int = Field(3600, description="Session timeout in seconds")
    MAX_PARTICIPANTS: int = Field(2, description="Maximum participants per session")
    CLEANUP_INTERVAL: int = Field(300, description="Background cleanup interval")
    
    # Security Settings
    TOKEN_ENTROPY_BITS: int = Field(256, description="Token entropy in bits")
    ENABLE_ENCRYPTION: bool = Field(True, description="Enable E2E encryption")
    ENABLE_MUTUAL_AUTH: bool = Field(True, description="Require mutual authentication")
    
    # Logging Configuration
    LOG_LEVEL: str = Field("INFO", description="Logging level")
    LOG_FILE: str = Field("p2p_broker.log", description="Log file path")
    
    # Production Settings
    DEBUG: bool = Field(False, description="Enable debug mode")
    RENDER_DEPLOYMENT: bool = Field(default_factory=lambda: bool(os.getenv("RENDER")), description="Running on Render")
    
    # Pydantic v2 configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  # Allow case insensitive env vars
        extra="ignore"
    )
    
    def get_log_level(self) -> str:
        """Get appropriate log level"""
        return self.LOG_LEVEL.upper()
    
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return self.RENDER_DEPLOYMENT or not self.DEBUG

# Global settings instance
settings = Settings()


# Example .env file content (create this file)
ENV_EXAMPLE = """
# Server Configuration
HOST=0.0.0.0
PORT=8000

# Security
ENABLE_ENCRYPTION=true
ENABLE_MUTUAL_AUTH=true

# Logging
LOG_LEVEL=INFO
DEBUG=false

# Optional Services
# REDIS_URL=redis://localhost:6379
# DATABASE_URL=sqlite:///./sessions.db
"""

if __name__ == "__main__":
    print("🔧 P2P Broker Configuration")
    print("=" * 40)
    print(f"Host: {settings.HOST}")
    print(f"Port: {settings.PORT}")
    print(f"Debug Mode: {settings.DEBUG}")
    print(f"Production Mode: {settings.is_production()}")
    print(f"Log Level: {settings.get_log_level()}")
    print("=" * 40)
    
    if not os.path.exists(".env"):
        print("\n💡 Create a .env file with:")
        print(ENV_EXAMPLE)
