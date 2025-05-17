import unittest
from utils import check_password_strength

class TestPasswordUtils(unittest.TestCase):
    def test_strength(self):
        self.assertFalse(check_password_strength("abc"))
        self.assertFalse(check_password_strength("abcdefg"))
        self.assertFalse(check_password_strength("abcdefg1"))
        self.assertFalse(check_password_strength("ABCDEFG1"))
        self.assertFalse(check_password_strength("Abcdefg1"))
        self.assertTrue(check_password_strength("Abcdefg1!"))

if __name__ == "__main__":
    unittest.main()
