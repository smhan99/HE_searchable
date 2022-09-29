/*******************************************************
 * Implementation of BGV Ciphertext Trie               *
 * Nodes are encryptionsof ASCII Encodings of          *
 * English Characters                                  *
 *******************************************************/

#include "trie.h"
using namespace std;


// Node::Node(char c) : ele(c), value(NULL) {}

// bool Node::hasNext(Node *cursor, char k) {
//   for (Node *n : children) {
//     if (n->ele == k) {
//       cursor = n;
//       cout << "TRUE: " << n->ele << endl;
//       return true;
//     }
//   }
//   cout << "FALSE" << endl;
//   return false;
// }

// Trie::Trie(char c) : root(new Node(c)) {}

// Node* Trie::search(vector<char> key) {
//   Node *cursor = root;
//   bool has_next = false;

//   for (int i = 0; i < key.size(); i++) {
//     if (cursor->children.size() == 0) return NULL;
//     for (Node *n : cursor->children) {
//       if (n->ele == key[i]) {
//         cursor = n;
//         has_next = true;
//         break;
//       }
//     }
//     if (!has_next) return NULL;
//     has_next = true;
//   }

//   return cursor->value; //if null, not found
// }

// void Trie::insert(vector<char> key, char value) {
//   Node *cursor = root;
//   bool has_next = false;

//   for (int i = 0; i < key.size(); i++) {
//     for (Node *n : cursor->children) {
//       if (n->ele == key[i]) {
//         cursor = n;
//         has_next = true;
//         break;
//       }
//     }
//     if (!has_next) {
//       Node *add = new Node(key[i]);
//       cursor->children.push_back(add);
//       cursor = add;
//     }
//     has_next = false;
//   }
//   if (cursor->value == NULL) {
//     Node *val = new Node(value);
//     cursor->value = val;
//   }
// }

Node::Node(helib::Ctxt ctxt) : 
  ele(ctxt), value(NULL) {}


//Require an empty Ctxt as root
Trie::Trie(helib::Ctxt ctxt) : root(new Node(ctxt)) {}

//Returns the node with value ciphertext
//Or NULL if not found
Node* Trie::search(vector<helib::Ctxt> key) {
  Node *cursor = root;
  bool has_next = false;
  
  for (int i = 0; i < key.size(); i++) {
    if (cursor->children.size() == 0) return NULL; //Not found
    for (Node *n : cursor->children) {
      if (n->ele.customCompare(key[i])) {
        cursor = n;
        has_next = true;
        break;
      }
    }
    if (!has_next) return NULL; //Not found
    has_next = false;
  }
  return cursor->value; //if null, not found
}

void Trie::insert(vector<helib::Ctxt> key, helib::Ctxt value) {
  Node *cursor = root;
  bool has_next = false;

  for (int i = 0; i < key.size(); i++) {
    for (Node *n : cursor->children) {
      if (n->ele.customCompare(key[i])) {
        cursor = n;
        has_next = true;
        break;
      }
    }
    if (!has_next) {
      Node *add = new Node(key[i]);
      cursor->children.push_back(add);
      cursor = add;
    }
    has_next = false;
  }
  if (cursor->value == NULL) {
    Node *val = new Node(value);
    cursor->value = val;
  }
}