#include <helib/helib.h>
#include <helib/ArgMap.h>

#include "binary.h"


using namespace helib;
using namespace std;

int main(int argc, char* argv[]) {
  unsigned long p = 2;
  unsigned long m = 19811;
  long r = 1;
  long c = 2;
  long bits = 350;
  long depth = 15;


  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("d", depth, "depth of binary tree calculation");
  amap.parse(argc, argv);

  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();
  
  helib::SecKey secret_key(context);
  secret_key.GenSecKey();
  addSome1DMatrices(secret_key);
  const helib::PubKey& public_key = secret_key;
  context.printout();

  //Initialize Binary Tree Database
  helib::Ptxt<helib::BGV> zeroP(context);
  helib::Ptxt<helib::BGV> oneP(context);
  for (int i = 0; i < context.getNSlots(); i++) {
    oneP.at(i) = 1;
  }
  zeroP.at(0) = 1;
    
  helib::Ctxt zero(public_key);
  helib::Ctxt one(public_key);
  public_key.Encrypt(zero, zeroP);
  public_key.Encrypt(one, oneP);

  helib::Ctxt test1 = one;
  helib::Ctxt test2 = one;
  helib::Ctxt test3 = one;
  cout << "test1.capacity= " << test1.capacity() << endl;
  cout << "test2.capacity= " << test2.capacity() << endl;
  cout << "test3.capacity= " << test3.capacity() << endl;
  cout << "one.capacity= " << one.capacity() << endl;
  rotate(test1, 1);
  rotate(test2, 2);
  rotate(test3, 6);
  cout << "test1.capacity= " << test1.capacity() << endl;
  cout << "test2.capacity= " << test2.capacity() << endl;
  cout << "test3.capacity= " << test3.capacity() << endl;
  cout << "one.capacity= " << one.capacity() << endl;
  rotate(test1, 1);
  rotate(test2, 2);
  rotate(test3, 6);
  cout << "test1.capacity= " << test1.capacity() << endl;
  cout << "test2.capacity= " << test2.capacity() << endl;
  cout << "test3.capacity= " << test3.capacity() << endl;
  cout << "one.capacity= " << one.capacity() << endl;
  rotate(test1, 1);
  rotate(test2, 2);
  rotate(test3, 6);
  cout << "test1.capacity= " << test1.capacity() << endl;
  cout << "test2.capacity= " << test2.capacity() << endl;
  cout << "test3.capacity= " << test3.capacity() << endl;
  cout << "one.capacity= " << one.capacity() << endl;
  rotate(test1, 1);
  rotate(test2, 2);
  rotate(test3, 6);
  cout << "test1.capacity= " << test1.capacity() << endl;
  cout << "test2.capacity= " << test2.capacity() << endl;
  cout << "test3.capacity= " << test3.capacity() << endl;
  cout << "one.capacity= " << one.capacity() << endl;
  return 0;

  helib::Ctxt query1 = zero;
  cout << "zero.capacity=" << zero.capacity() << endl;
  cout << "query.capacity" << query1.capacity() << endl;

  HELIB_NTIMER_START(rotate);
  for (int i = 0; i < 20; i++) {
    cout << i << ", ";
    helib::Ctxt query2 = one;
    query2 *= zero;
    query1 += query2;
    rotate(zero,1);
    cout << "zero.capacity=" << zero.capacity() << endl;
    cout << "query.capacity" << query1.capacity() << endl;
    // cout << "one.capacity=" << one.capacity() << " ";
  }
  HELIB_NTIMER_STOP(rotate);
  // cout << endl;
  cout << "Rotate Done" << endl;
  cout << "zero.capacity=" << zero.capacity() << endl;
  cout << "query.capacity" << query1.capacity() << endl;

  helib::Ptxt<helib::BGV> res(context);
  secret_key.Decrypt(res, query1);
  cout << res << endl;

  printNamedTimer(cout, "rotate");
  printNamedTimer(cout, "shift");
  return 0;
}