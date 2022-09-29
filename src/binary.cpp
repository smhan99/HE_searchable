/*******************************************************
 * Implementation of BGV Ciphertext Binary Tree        *
 * Nodes have values of ciphertext,                    *
 * And a vector pointer to 2 children nodes            *
 *******************************************************/

#include "binary.h"
using namespace std;


//BNode::BNode() {} deleted
BNode::BNode(helib::Ctxt c) : value(c), lChild(NULL), rChild(NULL) {}

bool BNode::noChildren() {
  return lChild == NULL && rChild == NULL;
}


void BinTree::updateHelper(BNode *ptr, vector<helib::Ctxt> key, helib::Ctxt value,
                           helib::Ctxt tmp, unsigned long ind) {
  // cout << ind << endl;
  helib::Ctxt l_val = l;            //left
  l_val += key[ind];                //compare
  l_val.addConstant(NTL::ZZX(1));   //compare
  l_val *= tmp;                     //mul by before

  helib::Ctxt r_val = r;            //right
  r_val += key[ind];                //compare
  r_val.addConstant(NTL::ZZX(1));   //compare
  r_val *= tmp;                     //mul by before

  if (ind == key.size() - 1) {
    //set left to tmp * left.compare(key[ind]) * value
    l_val *= value;                 //mul by value
    //set right to tmp * right.compare(key[ind]) * value
    r_val *= value;                 //mul by value

    if (ptr->noChildren()) {
      ptr->lChild = new BNode(l_val);
      ptr->rChild = new BNode(r_val);
    } else {
      l_val += ptr->lChild->value;
      ptr->lChild->value = l_val;
      r_val += ptr->rChild->value;
      ptr->rChild->value = r_val;
    }
    return;
  }
  if (ptr->noChildren()) {
    ptr->lChild = new BNode(tmp);
    ptr->rChild = new BNode(tmp);
  }

  updateHelper(ptr->lChild, key, value, l_val, ind + 1);
  updateHelper(ptr->rChild, key, value, r_val, ind + 1);
}

helib::Ctxt BinTree::searchHelper(BNode *ptr, vector<helib::Ctxt> *key, helib::Ctxt *res,
                    helib::Ctxt tmp, unsigned long ind, size_t last) {
  // cout << ind << endl;
  if (ptr->noChildren()) {
    return *res;
  }
  // helib::Ctxt l_val = l;                // left
  // l_val += key->at(ind);                //compare
  // l_val.addConstant(NTL::ZZX(1));       //compare
  // l_val *= tmp;                         //mul by before

  // helib::Ctxt r_val = r;                // right
  // r_val += key->at(ind);                //compare
  // r_val.addConstant(NTL::ZZX(1));       //compare
  // r_val *= tmp;                         //mul by before
  
  helib::Ctxt l_val = key->at(ind);
  l_val.addConstant(NTL::ZZX(1));
  helib::Ctxt r_val = l_val;
  l_val += l;
  l_val *= tmp;
  r_val += r;
  r_val *= tmp;

  
  if (ind == last) {
    l_val *= ptr->lChild->value; //mul by value on left
    *res += l_val;               //add to res
    r_val *= ptr->rChild->value; //mul by value on right
    *res += r_val;               //add to res
    return *res;
  }

  helib::Ctxt res2 = searchHelper(ptr->lChild, key, res, l_val, ind + 1, last);
  helib::Ctxt res3 = searchHelper(ptr->rChild, key, &res2, r_val, ind + 1, last);
  
  return res3;
}

void BinTree::createHelper(BNode* ptr, unsigned int ind, vector<helib::Ctxt> *values, size_t size) {
  // cout << ind << endl;
  ptr->lChild = new BNode(values->at(ind));
  if (ind + 1 >= size) {
    ptr->rChild = new BNode(l);
    return;
  }
  ptr->rChild = new BNode(values->at(ind + 1));

  ind = (2 * ind) + 2;
  if (ind >= size) return;
  createHelper(ptr->lChild, ind, values, size);
  ind += 2;
  if (ind >= size) return;
  createHelper(ptr->rChild, ind, values, size);
}

// BinTree::BinTree() : root(new BNode()) {} deleted

BinTree::BinTree(helib::Ctxt le, helib::Ctxt ri, helib::Ctxt rt) : 
  root(new BNode(rt)), l(le), r(ri) {}

helib::Ctxt BinTree::search(vector<helib::Ctxt> key) {
  helib::Ctxt res = root->value; //E(1)
  res.addConstant(NTL::ZZX(1)); // E(0)
  unsigned long i = 0;
  helib::Ctxt tmp = root->value; //E(1)
  helib::Ctxt result = searchHelper(root, &key, &res, tmp, i, key.size() - 1);
  return result;
}

void BinTree::update(vector<helib::Ctxt> key, helib::Ctxt value) {
  unsigned long i = 0;
  helib::Ctxt tmp = root->value; // E(1)
  updateHelper(root, key, value, tmp, i);
}

void BinTree::updateLR(helib::Ctxt le, helib::Ctxt ri) {
  l = le;
  r = ri;
}

void BinTree::createDB(vector<helib::Ctxt> values) {
  createHelper(root, 0, &values, values.size());
}