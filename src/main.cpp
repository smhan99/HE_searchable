#include "binary.h"

#include <helib/ArgMap.h>
#include <bitset>
#include <deque>
#include <sstream>

using namespace std;

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

int main(int argc, char* argv[]) {
  unsigned long p = 2;
  unsigned long m = 19811;
  unsigned long r = 1;
  unsigned long bits = 340;
  unsigned long c = 2;
  string db_filename = "countries_dataset";

  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("db_filename",
           db_filename,
           "Qualified name for the database filename");
  amap.parse(argc, argv);

  std::cout << "Initialising context object..." << std::endl;
  HELIB_NTIMER_START(timer_Context);
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();
  HELIB_NTIMER_STOP(timer_Context);

  // Print the context
  context.printout();
  std::cout << std::endl;
  // Print the security level
  std::cout << "Security: " << context.securityLevel() << std::endl;

  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context
  helib::SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  std::cout << "Generating key-switching matrices..." << std::endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const helib::PubKey& public_key = secret_key;

  /************ Read in the database ************/
  HELIB_NTIMER_START(timer_PopulateDB);
  std::cout << "Reading Database... " << std::endl;
  db_filename = "../../"+db_filename+".csv";
  vector<pair<string, string>> country_db;
  try {
    country_db = read_csv(db_filename);
  } catch (runtime_error& e) {
    cerr << "\n" << e.what() << std::endl;
    exit(1);
  }
  
  //Initialize Binary Tree Database
  helib::Ptxt<helib::BGV> zeroP(context);
  helib::Ptxt<helib::BGV> oneP(context);
  for (int i = 0; i < context.getNSlots(); i++)
    oneP.at(i) = 1;
  helib::Ctxt zero(public_key);
  helib::Ctxt one(public_key);
  helib::Ctxt root(public_key);
  public_key.Encrypt(zero, zeroP);
  public_key.Encrypt(one, oneP);
  public_key.Encrypt(root, oneP);
  BinTree db(zero, one, root);

  //Populate database
  HELIB_NTIMER_START(timer_encrypt);
  std::cout << "Encrypting values... " << std::endl;
  vector<helib::Ctxt> values;
  for (long i = 0; i < country_db.size(); i++) {
    // std::cout << country_db[i].first << std::endl;

    helib::Ptxt<helib::BGV> capital(context);
    stringstream ss;
    for (long j = 0; j < country_db[i].second.size(); ++j) {
      bitset<8> b(country_db[i].second[j]);
      ss << b;
    }
    for (long j = 0; j < ss.str().size(); j++)
      capital.at(j) = ss.str().at(j);
    helib::Ctxt capital_enc(public_key);
    public_key.Encrypt(capital_enc, capital);
    values.push_back(capital_enc);
  }
  HELIB_NTIMER_STOP(timer_encrypt);
  //Actual creation
  std::cout << "Populating db... " << std::endl;
  db.createDB(values);
  HELIB_NTIMER_STOP(timer_PopulateDB);

  helib::printNamedTimer(std::cout << std::endl, "timer_Context");
  helib::printNamedTimer(std::cout, "timer_encrypt");
  helib::printNamedTimer(std::cout, "timer_PopulateDB");

  std::cout << "\nInitialization Completed - Ready for Queries" << std::endl;
  std::cout << "--------------------------------------------" << std::endl;

  while (1) {
    /** Create the query **/
    // Read in query from the command line
    string query_string;
    std::cout << "\nPlease enter the index encoded code of an European Country: ";
    getline(cin, query_string);
    std::cout << "Looking for the Capital of " << query_string << std::endl;
    std::cout << "This may take few minutes ... " << std::endl;
    
    HELIB_NTIMER_START(timer_TotalQuery);

    HELIB_NTIMER_START(timer_EncryptQuery);
    vector<helib::Ctxt> query;
    for (int j = 0; j < query_string.size(); j++) {
      helib::Ctxt bit(public_key);
      long zo = query_string[j] - 48;
      // std::cout << zo << std::endl;
      if (zo) {
        public_key.Encrypt(bit, oneP);
        query.push_back(bit);
      } else {
        public_key.Encrypt(bit, zeroP);
        query.push_back(bit);
      }
    }
    HELIB_NTIMER_STOP(timer_EncryptQuery);

    /************ Perform the database search ************/

    HELIB_NTIMER_START(timer_QuerySearch);
    std::cout << "Searching ..." << std::endl;
    helib::Ctxt res = db.search(query);
    HELIB_NTIMER_STOP(timer_QuerySearch);

    /************ Decrypt and print result ************/

    HELIB_NTIMER_START(timer_DecryptQueryResult);
    helib::Ptxt<helib::BGV> plaintext_result(context);
    secret_key.Decrypt(plaintext_result, res);
    // std::cout << plaintext_result << std::endl;
    HELIB_NTIMER_STOP(timer_DecryptQueryResult);

    

    // Convert from ASCII to a string
    string string_result;
    long temp = 0;
    for (long i = 0; i < 64; ++i) {
      // std::cout << i << ":";
      long bit = static_cast<long>(plaintext_result[i]);
      // std::cout << bit << ", ";
      if (bit)
        temp += pow(2, (7 - (i % 8)) * bit);
      if (i % 8 == 7) {
        // std::cout << temp << std::endl;
        string_result.push_back(temp);
        // cout << string_result << endl;
        temp = 0;
      }
    }

    HELIB_NTIMER_STOP(timer_TotalQuery);

    std::cout << std::endl;

    if (string_result.at(0) == 0x00) {
      string_result =
          "Country name not in the database."
          "\n*** Please make sure to enter the name of a European Country"
          "\n*** with the first letter in upper case.";
    }

    std::cout << "\nQuery result: " << string_result << std::endl;
    helib::printNamedTimer(std::cout << std::endl, "timer_EncryptQuery");
    helib::printNamedTimer(std::cout, "timer_QuerySearch");
    helib::printNamedTimer(std::cout, "timer_DecryptQueryResult");
    helib::printNamedTimer(std::cout, "timer_TotalQuery");
  }
  return 0;
}