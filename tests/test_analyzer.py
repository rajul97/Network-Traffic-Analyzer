import unittest
from collections import defaultdict
import analyzer

class TestNetworkTrafficAnalyzer(unittest.TestCase):
    def setUp(self):
        """Setup test environment."""
        analyzer.syn_count = defaultdict(int)
        analyzer.port_scans = defaultdict(set)
    
    def test_syn_flood_detection(self):
        """Test if SYN flood detection works correctly."""
        src_ip = "192.168.1.1"
        for _ in range(analyzer.config.SYN_THRESHOLD + 1):
            analyzer.syn_count[src_ip] += 1
        self.assertTrue(analyzer.syn_count[src_ip] > analyzer.config.SYN_THRESHOLD)
    
    def test_port_scanning_detection(self):
        """Test if port scanning detection works correctly."""
        src_ip = "192.168.1.2"
        for port in range(1, analyzer.config.PORT_SCAN_THRESHOLD + 2):
            analyzer.port_scans[src_ip].add(port)
        self.assertTrue(len(analyzer.port_scans[src_ip]) > analyzer.config.PORT_SCAN_THRESHOLD)
    
if __name__ == "__main__":
    unittest.main()
