/*******************************************************
 * Implementation of BGV Ciphertext Trie               *
 * Nodes are encryptionsof ASCII Encodings of English  *
 * Characters                                          *
 *******************************************************/

#pragma once

#include <climits>
#include <fstream>
#include <iostream>
#include <sstream>

#include <helib/helib.h>

using namespace std;

// // Trie node
// class Node {
//   public:
//   char ele;
//   vector<Node*> children;
//   Node *value;
//   bool hasNext(Node *cursor, char k);


//     Node() = delete;
//     Node(char c);
// };

// class Trie {
//   public:
//   Node *root;
  
//   Trie(char c);
//   Node* search(vector<char> key);
//   void insert(vector<char> key, char value);
// };


// Trie node
class Node {
  helib::Ctxt ele;
  vector<Node*> children;
  Node *value;
  friend class Trie;

  public:
    Node() = delete;
    Node(helib::Ctxt c);
    helib::Ctxt getEle() { return ele; }
};

class Trie {
  Node *root;
  
  public:
  Trie(helib::Ctxt ctxt);
  Node* search(vector<helib::Ctxt> key);
  void insert(vector<helib::Ctxt> key, helib::Ctxt value);
};
