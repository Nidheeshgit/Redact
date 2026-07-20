import os
import unittest
import tempfile
import re
import csv
from werkzeug.security import generate_password_hash, check_password_hash

# Force imports from local workspace
import database as db
import redactor

class TestAdvancedFileRedactor(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Setup temporary SQLite database for testing
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        db.DATABASE_PATH = cls.db_path
        db.init_db()

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)

    def setUp(self):
        # Clean tables
        conn = db.get_db_connection()
        conn.execute('DELETE FROM users')
        conn.execute('DELETE FROM files')
        conn.execute('DELETE FROM file_analytics')
        conn.commit()
        conn.close()

    def test_database_detailed_analytics_lookup(self):
        """Tests that granular redaction counts are correctly saved and aggregated for charts."""
        p_hash = generate_password_hash("saaspass")
        user_id = db.create_user("Admin User", "admin@saas.com", p_hash)
        
        file_id = db.add_file(user_id, "finance.csv", "CSV", "Redacted", 10)
        
        # Add analytics breakdown
        stats = {
            'email': 2,
            'phone': 1,
            'pan': 3,
            'aadhaar': 2,
            'credit_card': 1,
            'manual': 1
        }
        db.add_file_analytics(file_id, user_id, stats)
        
        # Retrieve chart aggregate data
        analytics = db.get_detailed_analytics(user_id)
        
        self.assertEqual(analytics['pii_stats']['emails_removed'], 2)
        self.assertEqual(analytics['pii_stats']['phones_removed'], 1)
        self.assertEqual(analytics['pii_stats']['manual_redactions'], 1)
        
        dist = analytics['pii_stats']['distribution']
        self.assertEqual(dist['Emails'], 2)
        self.assertEqual(dist['PAN'], 3)
        self.assertEqual(dist['Aadhaar'], 2)
        self.assertEqual(dist['Credit Cards'], 1)
        self.assertEqual(dist['Manual Selection'], 1)
        self.assertEqual(dist['Passports'], 0) # Unused fields default to 0

    def test_pii_regex_matches_all_categories(self):
        """Tests that all 11 predefined regex categories detect sensitive details correctly."""
        content = (
            "Contact us at support@redact.com or 91-98765-43210.\n"
            "Personal Aadhaar number: 3344 5566 7788.\n"
            "Finance PAN: ABCDE1234F, Bank Account: 123456789012, IFSC: ICIC0000102.\n"
            "Visa Passport: Z1234567, DL: DL14-20110012345.\n"
            "UPI: name@okhdfcbank, Card: 1111-2222-3333-4444, Date: 20/07/2026."
        )
        
        active_patterns = {cat: True for cat in redactor.PATTERNS}
        custom_terms = []
        
        # Redact content
        red_content, total, counts = redactor.redact_text_content(
            content, active_patterns, custom_terms, style='custom', custom_label='[REDACTED]'
        )
        
        # Verify counts detected per category
        self.assertEqual(counts['email'], 1)
        self.assertEqual(counts['phone'], 1)
        self.assertEqual(counts['aadhaar'], 1)
        self.assertEqual(counts['pan'], 1)
        self.assertEqual(counts['passport'], 1)
        self.assertEqual(counts['dl'], 1)
        self.assertEqual(counts['bank'], 1)
        self.assertEqual(counts['ifsc'], 1)
        self.assertEqual(counts['credit_card'], 1)
        self.assertEqual(counts['upi'], 1)
        self.assertEqual(counts['date'], 1)
        self.assertEqual(total, 11)

    def test_redaction_masking_styles(self):
        """Tests that replacement styles (blackout, asterisks, crosses, labels) mask data properly."""
        text = "Confidential PAN: ABCDE1234F"
        active_patterns = {'pan': True}
        
        # 1. Blackout Style (solid block)
        red_black, _, _ = redactor.redact_text_content(text, active_patterns, [], style='blackout')
        self.assertIn("██████████", red_black)
        self.assertNotIn("ABCDE1234F", red_black)
        
        # 2. Asterisk Style
        red_ast, _, _ = redactor.redact_text_content(text, active_patterns, [], style='asterisk')
        self.assertIn("**********", red_ast)
        self.assertNotIn("ABCDE1234F", red_ast)
        
        # 3. Cross Style
        red_cross, _, _ = redactor.redact_text_content(text, active_patterns, [], style='cross')
        self.assertIn("XXXXXXXXXX", red_cross)
        self.assertNotIn("ABCDE1234F", red_cross)
        
        # 4. Custom Label
        red_custom, _, _ = redactor.redact_text_content(
            text, active_patterns, [], style='custom', custom_label='[PII_SCRUBBED]'
        )
        self.assertIn("[PII_SCRUBBED]", red_custom)
        self.assertNotIn("ABCDE1234F", red_custom)

    def test_casing_and_occurrence_rules(self):
        """Tests case sensitivity and occurrence scopes limits (first occurrence only)."""
        text = "Scrub target, Target, Target"
        
        # Case Insensitive + Redact All
        red1, count1, _ = redactor.redact_text_content(
            text, {}, ["target"], redact_all=True, case_sensitive=False
        )
        self.assertEqual(count1, 3)
        self.assertNotIn("target", red1.lower())
        
        # Case Sensitive + Redact All
        red2, count2, _ = redactor.redact_text_content(
            text, {}, ["Target"], redact_all=True, case_sensitive=True
        )
        self.assertEqual(count2, 2) # Matches only "Target", ignores lowercase "target"
        self.assertIn("Scrub target", red2)
        
        # Case Insensitive + First Occurrence Only
        red3, count3, _ = redactor.redact_text_content(
            text, {}, ["target"], redact_all=False, case_sensitive=False
        )
        self.assertEqual(count3, 1) # Only replaces the first match
        self.assertEqual(red3.count("[REDACTED]"), 1)

    def test_spreadsheet_coordinate_redactions(self):
        """Tests that specific cells, columns, and rows are successfully cleared in CSV tables."""
        csv_data = [
            ["ID", "Name", "Salary"],
            ["1", "Alice", "1000"],
            ["2", "Bob", "2000"],
            ["3", "Charlie", "3000"]
        ]
        
        fd_in, in_path = tempfile.mkstemp(suffix='.csv')
        fd_out, out_path = tempfile.mkstemp(suffix='.csv')
        
        try:
            with open(in_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(csv_data)
                
            # Request redaction: Cell B2 (Alice), Row 2 (Bob's row, index 2), and Col 2 (Salary col, index 2)
            cells = ['B2']     # "Alice"
            rows = [2]         # Row 2 (Index 2 -> "2, Bob, 2000" which is Row 3 in sheet)
            cols = [2]         # Col 2 (Salary column)
            
            success, total, counts, err = redactor.redact_file(
                in_path, out_path, {}, [], style='custom', custom_label='[REDACTED]',
                cells=cells, rows=rows, cols=cols
            )
            
            self.assertTrue(success)
            self.assertIsNone(err)
            
            # Read output back
            with open(out_path, 'r') as f:
                redacted_rows = list(csv.reader(f))
                
            self.assertEqual(redacted_rows[1][1], '[REDACTED]') # B2 cleared
            self.assertEqual(redacted_rows[2][1], '[REDACTED]') # Row 2 cell cleared
            self.assertEqual(redacted_rows[1][2], '[REDACTED]') # Col 2 (Salary) cleared
            
        finally:
            os.close(fd_in)
            os.close(fd_out)
            if os.path.exists(in_path): os.remove(in_path)
            if os.path.exists(out_path): os.remove(out_path)

if __name__ == '__main__':
    unittest.main()
