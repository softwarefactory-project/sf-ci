import unittest

class TestHello(unittest.TestCase):
    def test_hello(self):
        self.assertEqual(hello(), 'Hello Zuul')

def hello():
    return "Hello Zuul"

if __name__ == "__main__":
    print(hello())
