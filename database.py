import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'database', 'redaction.db')

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema with users, files, and file_analytics tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 2. Files Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            type TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            redactions_count INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # 3. File Analytics Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emails_count INTEGER DEFAULT 0,
            phones_count INTEGER DEFAULT 0,
            dates_count INTEGER DEFAULT 0,
            aadhaar_count INTEGER DEFAULT 0,
            pan_count INTEGER DEFAULT 0,
            passport_count INTEGER DEFAULT 0,
            dl_count INTEGER DEFAULT 0,
            bank_count INTEGER DEFAULT 0,
            ifsc_count INTEGER DEFAULT 0,
            credit_card_count INTEGER DEFAULT 0,
            upi_count INTEGER DEFAULT 0,
            manual_count INTEGER DEFAULT 0,
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

def create_user(name, email, password_hash):
    """Registers a new user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
            (name, email, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_file(user_id, filename, file_type, status, redactions_count=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO files (user_id, filename, type, status, redactions_count)
           VALUES (?, ?, ?, ?, ?)''',
        (user_id, filename, file_type, status, redactions_count)
    )
    conn.commit()
    file_id = cursor.lastrowid
    conn.close()
    return file_id

def update_file_status(file_id, status, redactions_count=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if redactions_count is not None:
        cursor.execute(
            'UPDATE files SET status = ?, redactions_count = ? WHERE id = ?',
            (status, redactions_count, file_id)
        )
    else:
        cursor.execute(
            'UPDATE files SET status = ? WHERE id = ?',
            (status, file_id)
        )
    conn.commit()
    conn.close()

def get_user_files(user_id, limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM files WHERE user_id = ? ORDER BY upload_date DESC LIMIT ?',
        (user_id, limit)
    )
    files = cursor.fetchall()
    conn.close()
    return files

def add_file_analytics(file_id, user_id, stats):
    """Inserts a row breaking down the redacted items for a specific file upload."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO file_analytics (
            file_id, user_id, emails_count, phones_count, dates_count,
            aadhaar_count, pan_count, passport_count, dl_count,
            bank_count, ifsc_count, credit_card_count, upi_count, manual_count
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            file_id, user_id,
            stats.get('email', 0), stats.get('phone', 0), stats.get('date', 0),
            stats.get('aadhaar', 0), stats.get('pan', 0), stats.get('passport', 0),
            stats.get('dl', 0), stats.get('bank', 0), stats.get('ifsc', 0),
            stats.get('credit_card', 0), stats.get('upi', 0), stats.get('manual', 0)
        )
    )
    conn.commit()
    conn.close()

def get_user_stats(user_id):
    """Calculates summary statistics for the user's dashboard cards."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (user_id,))
    total_files = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM files WHERE user_id = ? AND status = "Redacted"', (user_id,))
    total_redacted = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(redactions_count) FROM files WHERE user_id = ?', (user_id,))
    total_redactions = cursor.fetchone()[0]
    total_redactions = total_redactions if total_redactions is not None else 0
    
    conn.close()
    return {
        'total_files_uploaded': total_files,
        'total_files_redacted': total_redacted,
        'sensitive_data_detected': total_redactions
    }

def get_detailed_analytics(user_id):
    """Aggregates granular data from file_analytics and files to populate Chart.js."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Total metric counts
    cursor.execute('''
        SELECT 
            SUM(emails_count) as emails,
            SUM(phones_count) as phones,
            SUM(dates_count) as dates,
            SUM(aadhaar_count) as aadhaar,
            SUM(pan_count) as pan,
            SUM(passport_count) as passport,
            SUM(dl_count) as dl,
            SUM(bank_count) as bank,
            SUM(ifsc_count) as ifsc,
            SUM(credit_card_count) as credit_cards,
            SUM(upi_count) as upis,
            SUM(manual_count) as manual
        FROM file_analytics WHERE user_id = ?
    ''', (user_id,))
    row = cursor.fetchone()
    
    pii_stats = {
        'emails_removed': row['emails'] if row and row['emails'] is not None else 0,
        'phones_removed': row['phones'] if row and row['phones'] is not None else 0,
        'manual_redactions': row['manual'] if row and row['manual'] is not None else 0,
        'distribution': {
            'Emails': row['emails'] if row and row['emails'] is not None else 0,
            'Phones': row['phones'] if row and row['phones'] is not None else 0,
            'Dates': row['dates'] if row and row['dates'] is not None else 0,
            'Aadhaar': row['aadhaar'] if row and row['aadhaar'] is not None else 0,
            'PAN': row['pan'] if row and row['pan'] is not None else 0,
            'Passports': row['passport'] if row and row['passport'] is not None else 0,
            'DLs': row['dl'] if row and row['dl'] is not None else 0,
            'Bank Accounts': row['bank'] if row and row['bank'] is not None else 0,
            'IFSCs': row['ifsc'] if row and row['ifsc'] is not None else 0,
            'Credit Cards': row['credit_cards'] if row and row['credit_cards'] is not None else 0,
            'UPI IDs': row['upis'] if row and row['upis'] is not None else 0,
            'Manual Selection': row['manual'] if row and row['manual'] is not None else 0
        }
    }
    
    # 2. Daily uploads (last 7 days)
    cursor.execute('''
        SELECT DATE(upload_date) as date_str, COUNT(*) as count 
        FROM files 
        WHERE user_id = ? AND upload_date >= date('now', '-7 days')
        GROUP BY DATE(upload_date)
        ORDER BY date_str ASC
    ''', (user_id,))
    daily_rows = cursor.fetchall()
    daily_uploads = {r['date_str']: r['count'] for r in daily_rows}
    
    # 3. Weekly uploads (last 4 weeks)
    cursor.execute('''
        SELECT strftime('%W', upload_date) as week_num, COUNT(*) as count 
        FROM files 
        WHERE user_id = ? AND upload_date >= date('now', '-28 days')
        GROUP BY week_num
        ORDER BY week_num ASC
    ''', (user_id,))
    weekly_rows = cursor.fetchall()
    weekly_uploads = {f"Week {r['week_num']}": r['count'] for r in weekly_rows}
    
    # 4. Recent timeline (last 10 files redacted)
    cursor.execute('''
        SELECT f.filename, f.type, f.upload_date, f.redactions_count
        FROM files f
        WHERE f.user_id = ? AND f.status = 'Redacted'
        ORDER BY f.upload_date DESC LIMIT 10
    ''', (user_id,))
    timeline_rows = cursor.fetchall()
    timeline = [
        {
            'filename': r['filename'],
            'type': r['type'],
            'date': r['upload_date'],
            'count': r['redactions_count']
        }
        for r in timeline_rows
    ]
    
    conn.close()
    
    return {
        'pii_stats': pii_stats,
        'daily_uploads': daily_uploads,
        'weekly_uploads': weekly_uploads,
        'timeline': timeline
    }
