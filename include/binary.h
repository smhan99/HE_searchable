/*******************************************************
 * Implementation of BGV Ciphertext Binary Tree        *
 * Nodes have values of ciphertext,                    *
 * And a vector pointer to 2 children nodes            *
 *******************************************************/

#pragma once

#include <helib/helib.h>

using namespace std;

// BinTree node
class BNode {
  helib::Ctxt value;
  BNode *lChild;
  BNode *rChild;
  friend class BinTree;

  public:
    BNode() = delete;
    BNode(helib::Ctxt c);
    bool noChildren();
    //DEBUG purposes
    BNode* getLeft() { return lChild; }
    BNode* getRight() { return rChild; }
    void setLeft(BNode* bn) { lChild = bn; }
    void setRight(BNode* bn) { rChild = bn; }
    helib::Ctxt getVal() { return value; }
};

class BinTree {
  BNode *root;
  helib::Ctxt l; //set to E(0)
  helib::Ctxt r; //set to E(1)

  void updateHelper(BNode *ptr, vector<helib::Ctxt> key, helib::Ctxt value,
                    helib::Ctxt tmp, unsigned long ind);
  
  helib::Ctxt searchHelper(BNode *ptr, vector<helib::Ctxt> *key, helib::Ctxt *res,
                    helib::Ctxt tmp, unsigned long ind, size_t last);
  
  void createHelper(BNode* ptr, unsigned int ind, vector<helib::Ctxt> *values, size_t size);
                    
  public:
  BinTree() = delete;
  BinTree(helib::Ctxt le, helib::Ctxt ri, helib::Ctxt rt);
  helib::Ctxt search(vector<helib::Ctxt> key);
  void update(vector<helib::Ctxt> key, helib::Ctxt value);
  void updateLR(helib::Ctxt le, helib::Ctxt ri);
  BNode *getRoot() { return root; }
  void createDB(vector<helib::Ctxt> values);
};
