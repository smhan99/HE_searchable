#include <iostream>

#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

using namespace std;
using namespace helib;

// Utility function to read <K,V> CSV data from file
vector<pair<string, string>> read_csv(string filename)
{
  vector<pair<string, string>> dataset;
  ifstream data_file(filename);

  if (!data_file.is_open())
    throw runtime_error(
        "Error: This example failed trying to open the data file: " + filename +
        "\n           Please check this file exists and try again.");

  vector<string> row;
  string line, entry, temp;

  if (data_file.good()) {
    // Read each line of file
    while (getline(data_file, line)) {
      row.clear();
      stringstream ss(line);
      while (getline(ss, entry, ',')) {
        row.push_back(entry);
      }
      // Add key value pairs to dataset
      dataset.push_back(make_pair(row[0], row[1]));
    }
  }

  data_file.close();
  return dataset;
}

void searchRun(vector<pair<string, string>> country_db, long p, long m, long r, long bits, long c) {
  // try {
  cout << "Initializing the Context with m, p, r, bits, c: " << m << ", " << p << ", " << r << ", " << bits << ", " << c << endl;
  HELIB_NTIMER_START(timer_Context);
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                              .m(m)
                              .p(p)
                              .r(r)
                              .bits(bits)
                              .c(c)
                              .build();
  HELIB_NTIMER_STOP(timer_Context);
  double sec_lev = context.securityLevel();
  if (sec_lev < 110) {
    cout << "=============================================================" << endl;
    return;
  }
  cout << "***Security Level: " << context.securityLevel() << endl;
  cout << "***NSlots: " << context.getNSlots() << endl;
  cout << "=============================================================" << endl;

  //   // Secret key management
  //   cout << "\nKeyGen...";
  //   HELIB_NTIMER_START(timer_SecKey);
  //   // Create a secret key associated with the context
  //   helib::SecKey secret_key = helib::SecKey(context);
  //   // Generate the secret key
  //   secret_key.GenSecKey();
  //   HELIB_NTIMER_STOP(timer_SecKey);

  //   // Compute key-switching matrices that we need
  //   HELIB_NTIMER_START(timer_SKM);
  //   helib::addSome1DMatrices(secret_key);
  //   HELIB_NTIMER_STOP(timer_SKM);

  //   // Public key management
  //   // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
  //   HELIB_NTIMER_START(timer_PubKey);
  //   const helib::PubKey& public_key = secret_key;
  //   HELIB_NTIMER_STOP(timer_PubKey);

  //   cout << "Encoding into ptxt..." << endl;
  //   // Generating the Plain text representation of Country DB
  //   HELIB_NTIMER_START(timer_PtxtCountryDB);
  //   vector<helib::Ptxt<helib::BGV>> k_ptxt;
  //   vector<helib::Ptxt<helib::BGV>> v_ptxt;
  //   for (const auto& country_capital_pair : country_db) {
  //     helib::Ptxt<helib::BGV> country(context);
  //     helib::Ptxt<helib::BGV> capital(context);
  //     for (long i = 0; i < country_capital_pair.first.size(); ++i)
  //       country.at(i) = country_capital_pair.first[i];
  //     for (long i = 0; i < country_capital_pair.second.size(); ++i)
  //       capital.at(i) = country_capital_pair.second[i];
  //     k_ptxt.push_back(country);
  //     v_ptxt.push_back(capital);
  //   }
  //   HELIB_NTIMER_STOP(timer_PtxtCountryDB);

  //   // Encrypt the Country DB
  //   cout << "Encrypting the database..." << endl;
  //   HELIB_NTIMER_START(timer_CtxtCountryDB);
  //   vector<helib::Ctxt> k_ctxt;
  //   vector<helib::Ctxt> v_ctxt;
  //   for (long i = 0; i < k_ptxt.size(); i++) {
  //     helib::Ctxt encrypted_country(public_key);
  //     helib::Ctxt encrypted_capital(public_key);
  //     public_key.Encrypt(encrypted_country, k_ptxt[i]);
  //     public_key.Encrypt(encrypted_capital, v_ptxt[i]);
  //     k_ctxt.push_back(encrypted_country);
  //     v_ctxt.push_back(encrypted_capital);
  //   }

  //   HELIB_NTIMER_STOP(timer_CtxtCountryDB);
  //   helib::printNamedTimer(cout << endl, "timer_Context");
  //   helib::printNamedTimer(cout, "timer_Chain");
  //   helib::printNamedTimer(cout, "timer_SecKey");
  //   helib::printNamedTimer(cout, "timer_SKM");
  //   helib::printNamedTimer(cout, "timer_PubKey");
  //   helib::printNamedTimer(cout, "timer_PtxtCountryDB");
  //   helib::printNamedTimer(cout, "timer_CtxtCountryDB");

  //   cout << "\nInitialization Completed - Ready for Queries" << endl;
  //   cout << "--------------------------------------------" << endl;

  //   /** Create the query **/

  //   // Read in query from the command line
  //   string query_string = "Korea";
  //   cout << "Looking for the Capital of " << query_string << endl;
  //   cout << "This may take few minutes ... " << endl;

  //   HELIB_NTIMER_START(timer_TotalQuery);

  //   HELIB_NTIMER_START(timer_EncryptQuery);
  //   // Convert query to a numerical vector
  //   helib::Ptxt<helib::BGV> query_ptxt(context);
  //   for (long i = 0; i < query_string.size(); ++i)
  //     query_ptxt[i] = query_string[i];

  //   // Encrypt the query
  //   helib::Ctxt query(public_key);
  //   public_key.Encrypt(query, query_ptxt);
  //   HELIB_NTIMER_STOP(timer_EncryptQuery);

  //   /************ Perform the database search ************/

  //   HELIB_NTIMER_START(timer_QuerySearch);

  //   for (helib::Ctxt& key : k_ctxt) {
  //     key -= query;                   //difference
  //     key.power(p-1);                 //flt
  //     totalSums(key);                 //totalsum
  //     key.power(p-1);                 //flt
  //     key.negate();                   //negate
  //     key.addConstant(NTL::ZZX(1));   //add 1
  //     if (!key.isCorrect()) {
  //       cout << "Too much noise." << endl;
  //       cout << "=============================================================" << endl;
  //       return;
  //     }
  //   }
  //   helib::Ctxt res = helib::innerProduct(k_ctxt, v_ctxt);
  //   if (!res.isCorrect()) {
  //     cout << "Inner Product too much noise." << endl;
  //     cout << "=============================================================" << endl;
  //     return ;
  //   }

  //   HELIB_NTIMER_STOP(timer_QuerySearch);

  //   /************ Decrypt and print result ************/

  //   HELIB_NTIMER_START(timer_DecryptQueryResult);
  //   helib::Ptxt<helib::BGV> plaintext_result(context);
  //   secret_key.Decrypt(plaintext_result, res);
  //   HELIB_NTIMER_STOP(timer_DecryptQueryResult);

  //   // Convert from ASCII to a string
  //   string string_result;
  //   for (long i = 0; i < plaintext_result.size(); ++i)
  //     string_result.push_back(static_cast<long>(plaintext_result[i]));

  //   HELIB_NTIMER_STOP(timer_TotalQuery);
  //   helib::printNamedTimer(cout << endl, "timer_EncryptQuery");
  //   helib::printNamedTimer(cout, "timer_QuerySearch");
  //   helib::printNamedTimer(cout, "timer_DecryptQueryResult");

  //   cout << "\nQuery result: " << string_result << endl;
  //   helib::printNamedTimer(cout, "timer_TotalQuery");
  //   cout << "=============================================================" << endl;
  //   return;
  // } catch (OutOfRangeError oorErr) {
  //   cout << "Out of range error" << endl;
  //   cout << "m: " << m << endl;
  //   cout << "=============================================================" << endl;
  //   return;
  // }
}

bool isprime(long p) {
    bool ip = true;
    for (int i = 2; i <= p/2; i++) {
      if (p % i == 0) {
        ip = false;
        break;
      }
    }
    return ip;
}

long GCD(long a, long b) {
  if (b == 0) return a;
  return GCD(b, a % b);
}

long multiplicativeOrder(long A, long N) {
  if (GCD(A, N) != 1) return -1;
  long result = 1;
  long K = 1;
  while (K < N) {
    result = (result * A) % N;

    if (result == 1) return K;

    K++;
  }
  return -1;
}

long phi(long n) {
  long result = 1;
  for (int i = 2; i < n; i++)
    if (gcd(i, n) == 1)
      result++;
  return result;
}

int main(int argc, char* argv[])
{
  unsigned long r = 1;
  unsigned long c = 2;
  unsigned long p_low = 131;
  unsigned long p_high = 50000;

  helib::ArgMap amap;
  amap.arg("r", r, "Hensel lifting");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("p_low", p_low, "lower bound on range for p");
  amap.arg("p_high", p_high, "upper bound on range for p");
  amap.parse(argc, argv);

  // input database file name
  string db_filename = "../../countries_dataset.csv";
  /************ Read in the database ************/
  vector<pair<string, string>> country_db;
  try {
    country_db = read_csv(db_filename);
  } catch (runtime_error& e) {
    cerr << "\n" << e.what() << endl;
    exit(1);
  }

  // vector<long> p_vec = {15013, 20011, 25013, 30011, 35023, 40009};
  // vector<vector<long>> m_vecs = {{18481, 18539, 18739, 18721},
  //                               {18451, 18643},
  //                               {19381, 19501},
  //                               {19477, 19637, 19667},
  //                               {19099, 18679, 19109},
  //                               {20191, 19951, 20017}};
  // for (int i = 0; i < p_vec.size(); i++) {
    // long p = p_vec[i];
  long p = 131;
  cout << "Running ... " << p << endl;
  stringstream fss;
  fss << "alltrial_p" << p << "_c" << c << "_r" << r << ".txt";
  string fname = fss.str();

  ofstream out(fname);//ios_base::app
  streambuf *coutbuf = cout.rdbuf(); //save old buf
  cout.rdbuf(out.rdbuf()); //redirect cout to out.txt!

  for (long m = 12000; m < 20000; m++) {
    long tot = phi(m);
    long mo = multiplicativeOrder(p, m);
    long nslots = tot / mo;
    if (nslots < 200) continue;
    searchRun(country_db, p, m, 1, 350, 2);
  }

  HELIB_NTIMER_START(param_test);

  //   vector<long> m_vec = m_vecs[i];
  //   for (long i : m_vec)
  //     for (long bits = 400; bits <= 1000; bits+=50)
  //       searchRun(country_db, p, i, r, bits, c);

  // for (long i : m_vec_1024) {
  //   searchRun(country_db, p, i, r, 27, c);
  // }
  // cout << "phi(m) = 2048, p=" << p << ", bits=54 for standard 128bit security" << endl;
  // for (long i : m_vec_2048) {
  //   searchRun(country_db, p, i, r, 54, c);
  // }
  // cout << "phi(m) = 4096, p=" << p << ", bits=109 for standard 128bit security" << endl;
  // for (long i : m_vec_4096) {
  //   searchRun(country_db, p, i, r, 109, c);
  // }
  // cout << "phi(m) = 8192, p=" << p << ", bits=218 for standard 128bit security" << endl;
  // for (long i : m_vec_8192) {
  //   searchRun(country_db, p, i, r, 218, c);
  // }
  // cout << "phi(m) = 16384, p=" << p << ", bits=438 for standard 128bit security" << endl;
  // for (long i : m_vec_16384) {
  //   searchRun(country_db, p, i, r, 438, c);
  // }
  // cout << "phi(m) = 32768, p=" << p << ", bits=881 for standard 128bit security" << endl;
  // for (long i : m_vec_32768) {
  //   searchRun(country_db, p, i, r, 881, c);
  // }
    HELIB_NTIMER_STOP(param_test);
    printNamedTimer(cout, "param_test");
    cout.rdbuf(coutbuf); //reset to standard output again
    out.close();
    printNamedTimer(cout, "param_test");
  // }
  cout << "Done!" << endl;

  return 0;
}
