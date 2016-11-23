import unittest

from hello import app


class TestPost(unittest.TestCase):
    def test_post(self):

        self.test_app = app.test_client()

        response = self.test_app.get('/', content_type='html/text')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
