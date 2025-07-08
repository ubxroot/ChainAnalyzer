"""
Logger Utility Module
=====================

Provides comprehensive logging capabilities for ChainAnalyzer:
- Multi-level logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- File and console output
- Structured logging for analysis sessions
- Log rotation and management
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import json

def setup_logger(name: str = "ChainAnalyzer", 
                log_level: str = "INFO",
                log_file: Optional[str] = None,
                max_bytes: int = 10 * 1024 * 1024,  # 10MB
                backup_count: int = 5) -> logging.Logger:
    """
    Set up a comprehensive logger for ChainAnalyzer.
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup log files to keep
    
    Returns:
        Configured logger instance
    """
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            # Create log directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
        except Exception as e:
            logger.error(f"Failed to set up file logging: {e}")
    
    return logger

def setup_analysis_logger(session_id: str, 
                         analysis_type: str,
                         config: Dict[str, Any]) -> logging.Logger:
    """
    Set up a specialized logger for analysis sessions.
    
    Args:
        session_id: Unique session identifier
        analysis_type: Type of analysis (trace, monitor, threat_intel, etc.)
        config: Configuration dictionary
    
    Returns:
        Configured analysis logger
    """
    
    # Create session-specific log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"analysis_{analysis_type}_{session_id}_{timestamp}.log"
    
    # Get log directory from config or use default
    log_dir = config.get("logging", {}).get("log_directory", "logs")
    log_file = Path(log_dir) / log_filename
    
    # Set up logger
    logger = setup_logger(
        name=f"ChainAnalyzer.{analysis_type}.{session_id}",
        log_level=config.get("logging", {}).get("level", "INFO"),
        log_file=str(log_file)
    )
    
    # Log session start
    logger.info(f"Analysis session started: {session_id}")
    logger.info(f"Analysis type: {analysis_type}")
    logger.info(f"Configuration: {json.dumps(config, default=str)}")
    
    return logger

class AnalysisLogger:
    """Specialized logger for blockchain analysis operations."""
    
    def __init__(self, session_id: str, analysis_type: str, config: Dict[str, Any]):
        self.session_id = session_id
        self.analysis_type = analysis_type
        self.config = config
        self.logger = setup_analysis_logger(session_id, analysis_type, config)
        self.start_time = datetime.now()
        
        # Track analysis metrics
        self.metrics = {
            "transactions_processed": 0,
            "addresses_analyzed": 0,
            "alerts_generated": 0,
            "errors_encountered": 0,
            "processing_time": 0
        }
    
    def log_transaction_analysis(self, address: str, currency: str, 
                               transaction_count: int, risk_score: float):
        """Log transaction analysis results."""
        self.metrics["transactions_processed"] += transaction_count
        self.metrics["addresses_analyzed"] += 1
        
        self.logger.info(
            f"Transaction analysis completed - "
            f"Address: {address}, Currency: {currency}, "
            f"Transactions: {transaction_count}, Risk Score: {risk_score:.2f}"
        )
    
    def log_threat_analysis(self, address: str, threat_score: float, 
                          blacklist_matches: int, suspicious_indicators: int):
        """Log threat intelligence analysis results."""
        self.logger.info(
            f"Threat analysis completed - "
            f"Address: {address}, Threat Score: {threat_score:.2f}, "
            f"Blacklist Matches: {blacklist_matches}, "
            f"Suspicious Indicators: {suspicious_indicators}"
        )
    
    def log_risk_assessment(self, address: str, risk_level: str, 
                          risk_factors: int, recommendations: int):
        """Log risk assessment results."""
        self.logger.info(
            f"Risk assessment completed - "
            f"Address: {address}, Risk Level: {risk_level}, "
            f"Risk Factors: {risk_factors}, Recommendations: {recommendations}"
        )
    
    def log_alert(self, alert_type: str, severity: str, description: str, 
                 transaction_hash: Optional[str] = None):
        """Log security alerts."""
        self.metrics["alerts_generated"] += 1
        
        self.logger.warning(
            f"SECURITY ALERT - "
            f"Type: {alert_type}, Severity: {severity}, "
            f"Description: {description}, "
            f"Transaction: {transaction_hash or 'N/A'}"
        )
    
    def log_error(self, error_type: str, error_message: str, 
                 context: Optional[Dict[str, Any]] = None):
        """Log errors with context."""
        self.metrics["errors_encountered"] += 1
        
        error_data = {
            "error_type": error_type,
            "error_message": error_message,
            "context": context or {},
            "session_id": self.session_id,
            "analysis_type": self.analysis_type
        }
        
        self.logger.error(f"Analysis error: {json.dumps(error_data, default=str)}")
    
    def log_performance_metric(self, operation: str, duration: float, 
                             additional_data: Optional[Dict[str, Any]] = None):
        """Log performance metrics."""
        self.logger.info(
            f"Performance metric - "
            f"Operation: {operation}, Duration: {duration:.2f}s, "
            f"Additional Data: {additional_data or {}}"
        )
    
    def log_configuration_change(self, config_key: str, old_value: Any, new_value: Any):
        """Log configuration changes."""
        self.logger.info(
            f"Configuration changed - "
            f"Key: {config_key}, Old Value: {old_value}, New Value: {new_value}"
        )
    
    def log_api_request(self, api_name: str, endpoint: str, status_code: int, 
                       response_time: float, success: bool):
        """Log API request details."""
        level = logging.INFO if success else logging.WARNING
        
        self.logger.log(
            level,
            f"API request - "
            f"API: {api_name}, Endpoint: {endpoint}, "
            f"Status: {status_code}, Response Time: {response_time:.2f}s, "
            f"Success: {success}"
        )
    
    def log_monitoring_event(self, event_type: str, address: str, 
                           transaction_count: int, alert_count: int):
        """Log monitoring events."""
        self.logger.info(
            f"Monitoring event - "
            f"Type: {event_type}, Address: {address}, "
            f"Transactions: {transaction_count}, Alerts: {alert_count}"
        )
    
    def finalize_session(self):
        """Finalize the analysis session and log summary."""
        end_time = datetime.now()
        self.metrics["processing_time"] = (end_time - self.start_time).total_seconds()
        
        # Log session summary
        self.logger.info(
            f"Analysis session completed - "
            f"Session ID: {self.session_id}, "
            f"Duration: {self.metrics['processing_time']:.2f}s, "
            f"Transactions: {self.metrics['transactions_processed']}, "
            f"Addresses: {self.metrics['addresses_analyzed']}, "
            f"Alerts: {self.metrics['alerts_generated']}, "
            f"Errors: {self.metrics['errors_encountered']}"
        )
        
        # Save session metrics
        self._save_session_metrics()
    
    def _save_session_metrics(self):
        """Save session metrics to file."""
        try:
            metrics_file = Path("logs") / f"metrics_{self.session_id}.json"
            metrics_file.parent.mkdir(parents=True, exist_ok=True)
            
            metrics_data = {
                "session_id": self.session_id,
                "analysis_type": self.analysis_type,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "metrics": self.metrics,
                "config": self.config
            }
            
            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(metrics_data, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Failed to save session metrics: {e}")

def get_logger(name: str = "ChainAnalyzer") -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name)

def log_function_call(func_name: str, args: tuple, kwargs: dict, 
                     logger: Optional[logging.Logger] = None):
    """Decorator to log function calls."""
    if logger is None:
        logger = get_logger()
    
    logger.debug(f"Function call: {func_name}(args={args}, kwargs={kwargs})")

def log_execution_time(func_name: str, execution_time: float, 
                      logger: Optional[logging.Logger] = None):
    """Log function execution time."""
    if logger is None:
        logger = get_logger()
    
    logger.info(f"Function {func_name} executed in {execution_time:.2f} seconds") 
