# utils/advanced_logger.py
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

class AdvancedLogger:
    """Advanced logging utility for ChainAnalyzer."""
    
    def __init__(self, config: dict):
        self.config = config
        self.log_level = config.get('logging', {}).get('level', 'INFO')
        self.log_file = config.get('logging', {}).get('log_file', 'chainanalyzer.log')
        self.setup_logging()
    
    def setup_logging(self):
        """Setup advanced logging configuration."""
        # Create logs directory
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Configure logging format
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'
        
        # Setup root logger
        logging.basicConfig(
            level=getattr(logging, self.log_level.upper()),
            format=log_format,
            datefmt=date_format,
            handlers=[
                logging.FileHandler(log_dir / self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Create logger instance
        self.logger = logging.getLogger('ChainAnalyzer')
        
    def get_logger(self, name: str = None) -> logging.Logger:
        """Get logger instance."""
        if name:
            return logging.getLogger(name)
        return self.logger
    
    def log_analysis_start(self, address: str, currency: str):
        """Log analysis start."""
        self.logger.info(f"Starting analysis for {currency} address: {address}")
    
    def log_analysis_complete(self, address: str, duration: float):
        """Log analysis completion."""
        self.logger.info(f"Analysis complete for {address} in {duration:.2f}s")
    
    def log_error(self, error: Exception, context: str = ""):
        """Log error with context."""
        self.logger.error(f"Error in {context}: {str(error)}", exc_info=True)
