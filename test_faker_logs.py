import unittest
from app import create_app, db

class TestLogging(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_log_creation(self):
        # Test log creation
        response = self.client.post('/api/log', json={
            "level": "info",
            "message": "test log entry",
            "source": "unittest",
            "metadata": {}
        })
        self.assertEqual(response.status_code, 201)

    def test_log_fetching(self):
        # Test fetching logs
        self.client.post('/api/log', json={
            "level": "info",
            "message": "another test log entry",
            "source": "unittest",
            "metadata": {}
        })
        response = self.client.get('/api/logs')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(len(data) > 0)

if __name__ == '__main__':
    unittest.main()
