"""
Logger Module
=============

Provides comprehensive logging functionality:
- Configurable log levels
- File and console output
- Log rotation
- Structured logging
- Performance monitoring
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

class ChainAnalyzerLogger:
    """Advanced logging system for ChainAnalyzer."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_config = config.get("logging", {})
        self.logger = None
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        
        # Create logger
        self.logger = logging.getLogger("ChainAnalyzer")
        self.logger.setLevel(self._get_log_level())
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        if self.log_config.get("console_output", True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self._get_log_level())
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        # File handler
        if self.log_config.get("file_output", True):
            log_dir = Path(self.log_config.get("log_directory", "logs"))
            log_dir.mkdir(exist_ok=True)
            
            log_file = log_dir / f"chainanalyzer_{datetime.now().strftime('%Y%m%d')}.log"
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=self.log_config.get("max_file_size", 10 * 1024 * 1024),  # 10MB
                backupCount=self.log_config.get("backup_count", 5)
            )
            file_handler.setLevel(self._get_log_level())
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def _get_log_level(self) -> int:
        """Get log level from configuration."""
        level_str = self.log_config.get("level", "INFO").upper()
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        return level_map.get(level_str, logging.INFO)
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        self.logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self.logger.critical(message, extra=kwargs)
    
    def exception(self, message: str, **kwargs):
        """Log exception with traceback."""
        self.logger.exception(message, extra=kwargs)
    
    def log_transaction(self, tx_hash: str, currency: str, value: float, **kwargs):
        """Log transaction information."""
        self.info(f"Transaction: {tx_hash} | Currency: {currency} | Value: ${value:,.2f}", **kwargs)
    
    def log_analysis_start(self, address: str, currency: str, **kwargs):
        """Log analysis start."""
        self.info(f"Starting analysis for {currency} address: {address}", **kwargs)
    
    def log_analysis_complete(self, address: str, currency: str, duration: float, **kwargs):
        """Log analysis completion."""
        self.info(f"Analysis complete for {currency} address: {address} | Duration: {duration:.2f}s", **kwargs)
    
    def log_alert(self, alert_type: str, address: str, message: str, **kwargs):
        """Log alert."""
        self.warning(f"ALERT [{alert_type}] {address}: {message}", **kwargs)
    
    def log_api_request(self, service: str, endpoint: str, status_code: int, duration: float, **kwargs):
        """Log API request."""
        self.debug(f"API Request: {service} | {endpoint} | Status: {status_code} | Duration: {duration:.2f}s", **kwargs)
    
    def log_error_with_context(self, error: Exception, context: str, **kwargs):
        """Log error with context."""
        self.error(f"Error in {context}: {str(error)}", **kwargs)
    
    def get_logger(self) -> logging.Logger:
        """Get the underlying logger instance."""
        return self.logger
    
    def set_level(self, level: str):
        """Set log level dynamically."""
        self.log_config["level"] = level
        self._setup_logging()
    
    def get_log_files(self) -> list:
        """Get list of log files."""
        log_dir = Path(self.log_config.get("log_directory", "logs"))
        if log_dir.exists():
            return [str(f) for f in log_dir.glob("*.log")]
        return []
    
    def clear_logs(self):
        """Clear all log files."""
        log_dir = Path(self.log_config.get("log_directory", "logs"))
        if log_dir.exists():
            for log_file in log_dir.glob("*.log"):
                log_file.unlink()
            self.info("All log files cleared")
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics."""
        log_files = self.get_log_files()
        
        stats = {
            "log_files_count": len(log_files),
            "current_level": self.log_config.get("level", "INFO"),
            "console_output": self.log_config.get("console_output", True),
            "file_output": self.log_config.get("file_output", True),
            "max_file_size": self.log_config.get("max_file_size", 10 * 1024 * 1024),
            "backup_count": self.log_config.get("backup_count", 5)
        }
        
        return stats
