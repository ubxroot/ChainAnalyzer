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
        self.start_time = None
    
    @contextmanager
    def measure(self, operation_name: str):
        """Measure operation performance."""
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        # Set start time for total analysis if this is the first measurement
        if self.start_time is None:
            self.start_time = start_time
        
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
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        # Calculate total analysis time
        if self.start_time:
            total_time = time.time() - self.start_time
            self.measurements['total_analysis'] = total_time
        else:
            self.measurements['total_analysis'] = 0.0
        
        return {
            **self.measurements,
            'system_stats': self.system_stats
        }
