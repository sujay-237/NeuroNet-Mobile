class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class SignatureTrie:
    def __init__(self):
        self.root = TrieNode()
        # Pre-load known signatures
        self.insert("admin' --")
        self.insert("UNION SELECT")

    def insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        self.is_end = True

    def search(self, payload):
        # A real implementation would scan the string for these signatures
        # For simplicity, we just check exact matches in this demo
        node = self.root
        for char in payload:
            if char in node.children:
                node = node.children[char]
                if node.is_end: return True
            else:
                return False
        return False