# utils/performance_monitor.py
import time
from contextlib import contextmanager

class PerformanceMonitor:
    """Performance monitoring utility."""
    
    def __init__(self):
        self.measurements = {}
    
    @contextmanager
    def measure(self, operation_name: str):
        """Measure operation performance."""
        start_time = time.time()
        try:
            yield
        finally:
            end_time = time.time()
            self.measurements[operation_name] = end_time - start_time
    
    def get_summary(self) -> dict:
        """Get performance summary."""
        return self.measurements
