import os
import tempfile
import unittest
from src.analyze_pcap import analyze

class AnalyzerTests(unittest.TestCase):
    def test_unusual_domain_detection(self):
        content = (
            "frame.time,ip.src,ip.dst,udp.srcport,udp.dstport,dns.qry.name,frame.len\n"
            "2026-01-01,10.0.0.2,10.0.0.1,53000,53,wpad.easyas123.tech,90\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv") as f:
            f.write(content)
            name = f.name
        try:
            _, findings, _ = analyze(name)
            self.assertTrue(any(x["rule"] == "Unusual WPAD/custom domain observed" for x in findings))
        finally:
            os.unlink(name)

    def test_empty_csv_rows(self):
        content = "frame.time,ip.src,ip.dst,frame.len\n2026-01-01,10.0.0.2,10.0.0.1,64\n"
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv") as f:
            f.write(content)
            name = f.name
        try:
            summary, findings, _ = analyze(name)
            self.assertEqual(summary["rows_total"], 1)
            self.assertEqual(summary["rows_with_ip"], 1)
        finally:
            os.unlink(name)

if __name__ == "__main__":
    unittest.main()
