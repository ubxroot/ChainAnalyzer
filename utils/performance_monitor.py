# utils/performance_monitor.py
import time
import psutil
import threading
from contextlib import contextmanager
from typing import Dict, Any
import logging

class PerformanceMonitor:
    """Enhanced performance monitoring utility."""
    
    def __init__(self):
        self.measurements = {}
        self.system_stats = {}
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread = None
    
    @contextmanager
    def measure(self, operation_name: str):
        """Measure operation performance."""
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        try:
            yield
        finally:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            self.measurements[operation_name] = {
                'duration': end_time - start_time,
                'memory_used': end_memory - start_memory,
                'start_memory': start_memory,
                'end_memory': end_memory
            }
    
    def start_system_monitoring(self):
        """Start continuous system monitoring."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_system)
        self.monitor_thread.start()
    
    def stop_system_monitoring(self):
        """Stop system monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_system(self):
        """Monitor system resources."""
        while self.monitoring:
            self.system_stats = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'timestamp': time.time()
            }
            time.sleep(1)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        return {
            **self.measurements,
            'system_stats': self.system_stats
        }
