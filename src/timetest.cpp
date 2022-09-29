#include <helib/helib.h>

#include <helib/ArgMap.h>

int main(int argc, char* argv[])
{
  /*  Example of BGV scheme  */

  // Plaintext prime modulus
  unsigned long p = 131;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 130;
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 1000;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;
  // std::vector<long> mvec = {5, 31, 79};
  // // Generating set of Zm* group.
  // std::vector<long> gens = {2341, 3277, 911};
  // // Orders of the previous generators.
  // std::vector<long> ords = {6, 4, 6};

  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.parse(argc, argv);

  std::cout << "Initialising context object..." << std::endl;
  // Initialize context
  // This object will hold information about the algebra created from the
  // previously set parameters
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                              // .gens(gens)
                               //.ords(ords)
                               .bits(bits)
                               .c(c)
                               //.bootstrappable(true)
                               //.mvec(mvec)
                               .build();

  // Print the context
  context.printout();
  std::cout << std::endl;

  // Print the security level
  std::cout << "Security: " << context.securityLevel() << std::endl;

  // Secret key management
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context
  helib::SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  std::cout << "Generating key-switching matrices..." << std::endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);
  // secret_key.genRecryptData();

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const helib::PubKey& public_key = secret_key;

  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = context.getEA();

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

  // Create a vector of long with nslots elements
  helib::Ptxt<helib::BGV> ptxt(context);
  helib::Ptxt<helib::BGV> ptxt2(context);
  helib::Ptxt<helib::BGV> ptxt3(context);
  for (int i = 0; i < ptxt.size(); ++i) {
    ptxt[i] = i;
    if (i%2==0) ptxt2[i]=1;
  }

  // Print the plaintext
  std::cout << "Initial Plaintext: " << ptxt << std::endl;
  std::cout << "Other Plaintext: " << ptxt2 << std::endl;

  // Create a ciphertext object
  helib::Ctxt ctxt(public_key);
  helib::Ctxt ctxt2(public_key);
  // helib::Ctxt ctxt3(public_key);
  // // // Encrypt the plaintext using the public_key
  public_key.Encrypt(ctxt, ptxt);
  // public_key.Encrypt(ctxt2, ptxt2);

  ctxt.frobeniusAutomorph(31);
  helib::Ptxt<helib::BGV> dec(context);
  secret_key.Decrypt(dec, ctxt);
  std::cout << "Decrypted: " << dec << std::endl;
  return 0;
  // public_key.Encrypt(ctxt3, ptxt3);
  // helib::Ctxt tmp1 = ctxt;
  // std::cout << (ctxt == tmp1) << std::endl;
  // tmp1 *= ctxt2;
  // helib::Ctxt tmp2 = ctxt;
  // tmp2 += ctxt3;
  // std::cout << (ctxt == tmp1) << std::endl;
  // std::cout << ctxt.equalsTo(tmp1) << std::endl;
  // std::cout << (ctxt == tmp2) << std::endl;
  // std::cout << ctxt.equalsTo(tmp2) << std::endl;
  // tmp2 -= ctxt3;
  // std::cout << (ctxt == tmp2) << std::endl;

  // std::vector<helib::Ctxt> v1;
  // std::vector<helib::Ctxt> v2;
  // for (int i = 0; i < 5; i++) {
  //   v1.push_back(ctxt);
  //   v2.push_back(ctxt2);
  // }

  // helib::Ctxt res = helib::innerProduct(v1, v2);
  // helib::Ptxt<helib::BGV> decres(context);
  // secret_key.Decrypt(decres, res);
  // std::cout << "innerProd" << decres << std::endl;
  // return 0;

  helib::Ctxt query(public_key);
  public_key.Encrypt(query, ptxt);

  helib::Ctxt mask(public_key);
  // std::vector<helib::Ctxt> mask;
  // mask.reserve(1);
  HELIB_NTIMER_START(all);
  ctxt -= query;
  HELIB_NTIMER_START(bulk);
  ctxt.power(p-1);
  totalSums(ctxt);
  ctxt.power(p-1);
  HELIB_NTIMER_STOP(bulk);
  ctxt.negate();
  ctxt.addConstant(NTL::ZZX(1));
  HELIB_NTIMER_STOP(all);
  std::cout << ctxt.isCorrect() << std::endl;
  helib::printNamedTimer(std::cout, "bulk");
  helib::printNamedTimer(std::cout, "all");
  // std::vector<helib::Ctxt> v1;
  // std::vector<helib::Ctxt> v2;
  // for (int i = 0; i < 50; i++) {
  //   v1.push_back(ctxt);
  //   v2.push_back(ctxt2);
  // }
  // helib::Ctxt res = helib::innerProduct(v1, v2);
  // std::cout << res.isCorrect() << std::endl;

  // HELIB_NTIMER_START(all);
  // HELIB_NTIMER_START(init);
  // helib::Ctxt test_ctxt = ctxt;
  // HELIB_NTIMER_STOP(init);
  // HELIB_NTIMER_START(difference);
  // test_ctxt -= query;
  // HELIB_NTIMER_STOP(difference);
  // HELIB_NTIMER_START(flt1);  
  // test_ctxt.power(p - 1);                       // init flt
  // HELIB_NTIMER_STOP(flt1);
  // HELIB_NTIMER_START(negate);
  // test_ctxt.negate();                           // negate
  // HELIB_NTIMER_STOP(negate);
  // HELIB_NTIMER_START(addConstant);
  // test_ctxt.addConstant(NTL::ZZX(1));           // 1-flt, 1 if eq, 0 otw
  // HELIB_NTIMER_STOP(addConstant);
  // HELIB_NTIMER_STOP(all);
  // helib::printNamedTimer(std::cout, "init");
  // helib::printNamedTimer(std::cout, "difference");
  // helib::printNamedTimer(std::cout, "flt1");
  // helib::printNamedTimer(std::cout, "negate");
  // helib::printNamedTimer(std::cout, "addConstant");
  // helib::printNamedTimer(std::cout, "all");


  // HELIB_NTIMER_START(all);
  // HELIB_NTIMER_START(init);
  // helib::Ctxt test_ctxt = ctxt;
  // HELIB_NTIMER_STOP(init);
  // HELIB_NTIMER_START(difference);
  // test_ctxt -= query;
  // HELIB_NTIMER_STOP(difference);
  // HELIB_NTIMER_START(flt);
  // test_ctxt.power(p-1);
  // HELIB_NTIMER_STOP(flt);
  // HELIB_NTIMER_START(negate);
  // test_ctxt.negate();
  // HELIB_NTIMER_STOP(negate);
  // HELIB_NTIMER_START(addConstant);
  // test_ctxt.addConstant(NTL::ZZX(1));
  // HELIB_NTIMER_STOP(addConstant);
  // HELIB_NTIMER_START(rotateAndProduct);
  // std::vector<helib::Ctxt> rorated_test_ctxt(ea.size(), test_ctxt);
  // HELIB_NTIMER_START(rotate);
  // for (int i = 1; i < rorated_test_ctxt.size(); i++)
  //   ea.rotate(rorated_test_ctxt[i], i);
  // HELIB_NTIMER_STOP(rotate);
  // HELIB_NTIMER_START(totalProduct);
  // totalProduct(test_ctxt, rorated_test_ctxt);
  // HELIB_NTIMER_STOP(totalProduct);
  // HELIB_NTIMER_STOP(rotateAndProduct);
  // HELIB_NTIMER_START(multiplyBy);
  // test_ctxt.multiplyBy(ctxt);
  // HELIB_NTIMER_STOP(multiplyBy);
  // HELIB_NTIMER_START(pushBack);
  // mask.push_back(test_ctxt);
  // HELIB_NTIMER_STOP(pushBack);
  // HELIB_NTIMER_STOP(all);
  // helib::printNamedTimer(std::cout, "init");
  // helib::printNamedTimer(std::cout, "difference");
  // helib::printNamedTimer(std::cout, "flt");
  // helib::printNamedTimer(std::cout, "negate");
  // helib::printNamedTimer(std::cout, "addConstant");
  // helib::printNamedTimer(std::cout, "rotate");
  // helib::printNamedTimer(std::cout, "totalProduct");
  // helib::printNamedTimer(std::cout, "rotateAndProduct");
  // helib::printNamedTimer(std::cout, "multiplyby");
  // helib::printNamedTimer(std::cout, "pushBack");
  // helib::printNamedTimer(std::cout, "all");  

  // HELIB_NTIMER_START(all);
  // HELIB_NTIMER_START(init);
  // helib::Ctxt test_ctxt = ctxt;
  // HELIB_NTIMER_STOP(init);
  // HELIB_NTIMER_START(difference);
  // test_ctxt -= query;
  // HELIB_NTIMER_STOP(difference);
  // HELIB_NTIMER_START(flt1);  
  // test_ctxt.power(p - 1);                       // init flt
  // HELIB_NTIMER_STOP(flt1);
  // HELIB_NTIMER_START(totalSum);
  // totalSums(test_ctxt);
  // HELIB_NTIMER_STOP(totalSum);
  // HELIB_NTIMER_START(flt2);  
  // test_ctxt.power(p - 1);                       // init flt
  // HELIB_NTIMER_STOP(flt2);
  // HELIB_NTIMER_START(negate);
  // test_ctxt.negate();                           // negate
  // HELIB_NTIMER_STOP(negate);
  // HELIB_NTIMER_START(addConstant);
  // test_ctxt.addConstant(NTL::ZZX(1));           // 1-flt, 1 if eq, 0 otw
  // HELIB_NTIMER_STOP(addConstant);
  // HELIB_NTIMER_START(multiplyBy);
  // test_ctxt.multiplyBy(ctxt);
  // HELIB_NTIMER_STOP(multiplyBy);
  // HELIB_NTIMER_START(maskAddCtxt);
  // mask += test_ctxt;
  // HELIB_NTIMER_STOP(maskAddCtxt);
  // HELIB_NTIMER_STOP(all);
  // helib::printNamedTimer(std::cout, "init");
  // helib::printNamedTimer(std::cout, "difference");
  // helib::printNamedTimer(std::cout, "flt1");
  // helib::printNamedTimer(std::cout, "totalSum");
  // helib::printNamedTimer(std::cout, "flt2");
  // helib::printNamedTimer(std::cout, "negate");
  // helib::printNamedTimer(std::cout, "addConstant");
  // helib::printNamedTimer(std::cout, "multiplyBy");
  // helib::printNamedTimer(std::cout, "maskAddCtxt");
  // helib::printNamedTimer(std::cout, "all");                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, ctxt);
  std::cout << plaintext_result << std::endl;
  // helib::Ptxt<helib::BGV> plaintext_result2(context);
  // secret_key.Decrypt(plaintext_result2, res);
  // std::cout << plaintext_result2 << std::endl;
  return 0;
}