from database.connection import get_db

class ScanJobRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def create(self, site_id, target_cidr):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_jobs (site_id, target_cidr, status, progress, current_step)
                VALUES (?, ?, 'RUNNING', 5, 'Iniciando escaneo de red...')
            """, (site_id, target_cidr))
            return cursor.lastrowid

    def update_progress(self, job_id, progress, current_step, discovered_count=None):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            if discovered_count is not None:
                cursor.execute("""
                    UPDATE scan_jobs
                    SET progress = ?, current_step = ?, discovered_count = ?
                    WHERE id = ?
                """, (progress, current_step, discovered_count, job_id))
            else:
                cursor.execute("""
                    UPDATE scan_jobs
                    SET progress = ?, current_step = ?
                    WHERE id = ?
                """, (progress, current_step, job_id))

    def complete(self, job_id, discovered_count, warnings=""):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_jobs
                SET status = 'COMPLETED', progress = 100, current_step = 'Escaneo completado con éxito',
                    discovered_count = ?, warnings = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (discovered_count, warnings, job_id))

    def fail(self, job_id, error_message):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_jobs
                SET status = 'FAILED', current_step = 'Error durante el escaneo',
                    error_message = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (str(error_message), job_id))

    def get_by_id(self, job_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_latest_by_site(self, site_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM scan_jobs WHERE site_id = ? ORDER BY id DESC LIMIT 1",
                (site_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
