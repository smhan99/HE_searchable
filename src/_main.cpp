#include "trie.h"

#include <helib/ArgMap.h>

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
  unsigned long p = 131;
  unsigned long m = 24461;
  unsigned long r = 1;
  unsigned long bits = 450;
  unsigned long c = 4;
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

  cout << "Initialising context object..." << endl;
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
  cout << endl;
  // Print the security level
  cout << "Security: " << context.securityLevel() << endl;

  cout << "Creating secret key..." << endl;
  // Create a secret key associated with the context
  helib::SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  cout << "Generating key-switching matrices..." << endl;
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const helib::PubKey& public_key = secret_key;

  //Init Index
  HELIB_NTIMER_START(timer_IndexInit);
  cout << "Initializing index... " << endl;
  unordered_map<char, helib::Ctxt> index;
  for (int i = 32; i < 127; i++) {
    char c = i;
    helib::Ptxt<helib::BGV> ptxt(context);
    ptxt.at(0) = i;
    helib::Ctxt ctxt(public_key);
    public_key.Encrypt(ctxt, ptxt);
    index.emplace(c, ctxt);
  }
  HELIB_NTIMER_STOP(timer_IndexInit);

  /************ Read in the database ************/
  HELIB_NTIMER_START(timer_PopulateDB);
  cout << "Reading Database... " << endl;
  db_filename = "../../"+db_filename+".csv";
  vector<pair<string, string>> country_db;
  try {
    country_db = read_csv(db_filename);
  } catch (runtime_error& e) {
    cerr << "\n" << e.what() << endl;
    exit(1);
  }
  
  //Initialize Trie Database
  helib::Ctxt empty(public_key);
  Trie db(empty);

  //Populate database
  cout << "Populating db... " << endl;
  for (const auto& country_capital_pair : country_db) {
    vector<helib::Ctxt> country;
    helib::Ptxt<helib::BGV> capital(context);
    for (long i = 0; i < country_capital_pair.first.size(); ++i) {
      country.emplace_back(index.at(country_capital_pair.first[i]));
    }
    cout << country_capital_pair.second << endl;
    for (long i = 0; i < country_capital_pair.second.size(); ++i)
      capital.at(i) = country_capital_pair.second[i];
    helib::Ctxt capital_enc(public_key);
    public_key.Encrypt(capital_enc, capital);
    db.insert(country, capital_enc);
  }
  HELIB_NTIMER_STOP(timer_PopulateDB);

  helib::printNamedTimer(cout << endl, "timer_Context");
  helib::printNamedTimer(cout, "timer_IndexInit");
  helib::printNamedTimer(cout, "timer_PopulateDB");

  cout << "\nInitialization Completed - Ready for Queries" << endl;
  cout << "--------------------------------------------" << endl;

  /** Create the query **/

  // Read in query from the command line
  string query_string;
  cout << "\nPlease enter the name of an European Country: ";
  getline(cin, query_string);
  cout << "Looking for the Capital of " << query_string << endl;
  cout << "This may take few minutes ... " << endl;
  
  HELIB_NTIMER_START(timer_TotalQuery);

  HELIB_NTIMER_START(timer_EncryptQuery);
  vector<helib::Ctxt> query;
  for (long i = 0; i < query_string.size(); ++i) {
    query.emplace_back(index.at(query_string[i]));
  }
  HELIB_NTIMER_STOP(timer_EncryptQuery);

  /************ Perform the database search ************/

  HELIB_NTIMER_START(timer_QuerySearch);
  Node *result = db.search(query);
  HELIB_NTIMER_STOP(timer_QuerySearch);
  if (result == NULL) {
    cout <<
        "Country name not in the database."
        "\n*** Please make sure to enter the name of a European Country"
        "\n*** with the first letter in upper case."
    << endl;
    return 0;
  }
  helib::Ctxt res = result->getEle();

  /************ Decrypt and print result ************/

  HELIB_NTIMER_START(timer_DecryptQueryResult);
  helib::Ptxt<helib::BGV> plaintext_result(context);
  // secret_key.Decrypt(plaintext_result, mask);
  secret_key.Decrypt(plaintext_result, res);
  HELIB_NTIMER_STOP(timer_DecryptQueryResult);

  // Convert from ASCII to a string
  string string_result;
  for (long i = 0; i < plaintext_result.size(); ++i)
    string_result.push_back(static_cast<long>(plaintext_result[i]));

  HELIB_NTIMER_STOP(timer_TotalQuery);

  cout << "\nQuery result: " << string_result << endl;
  helib::printNamedTimer(cout << endl, "timer_EncryptQuery");
  helib::printNamedTimer(cout, "timer_QuerySearch");
  helib::printNamedTimer(cout, "timer_DecryptQueryResult");
  helib::printNamedTimer(cout, "timer_TotalQuery");
  return 0;
}