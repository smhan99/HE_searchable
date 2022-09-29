#include <helib/helib.h>

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
  unsigned long p = 131;
  unsigned long m = 17981;
  unsigned long r = 1;
  unsigned long bits = 350;
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
  HELIB_NTIMER_START(timer_DB);
  std::cout << "Reading Database... " << std::endl;
  db_filename = "../../"+db_filename+".csv";
  vector<pair<string, string>> country_db;
  try {
    country_db = read_csv(db_filename);
  } catch (runtime_error& e) {
    cerr << "\n" << e.what() << std::endl;
    exit(1);
  }
  
  HELIB_NTIMER_START(timer_makePtxt);
  std::cout << "Making plaintext... " << std::endl;
  vector<helib::Ptxt<helib::BGV>> ptxt_db;
  for (int i = 0; i < country_db.size(); i++) {
    int count = 0;
    for (int j = 0; j < ptxt_db.size(); j++) {
      if (count == country_db[i].second.size()) break;
      ptxt_db[j].at(count + i) = country_db[i].second[count];
      count++;
    }
    while (count < country_db[i].second.size()) {
      helib::Ptxt<helib::BGV> new_ptxt(context);
      new_ptxt.at(count + i) = country_db[i].second[count];
      count++;
      ptxt_db.push_back(new_ptxt);
    }
  }
  HELIB_NTIMER_STOP(timer_makePtxt);

  //Populate database
  HELIB_NTIMER_START(timer_encrypt);
  std::cout << "Populating db... " << std::endl;
  vector<helib::Ctxt> database;
  for (auto p : ptxt_db) {
    helib::Ctxt c(public_key);
    public_key.Encrypt(c, p);
    database.push_back(c);
  }
  HELIB_NTIMER_STOP(timer_encrypt);
  HELIB_NTIMER_STOP(timer_DB);

  helib::printNamedTimer(std::cout << std::endl, "timer_Context");
  helib::printNamedTimer(std::cout, "timer_makePtxt");
  helib::printNamedTimer(std::cout, "timer_encrypt");
  helib::printNamedTimer(std::cout, "timer_DB");

  std::cout << "\nInitialization Completed - Ready for Queries" << std::endl;
  std::cout << "--------------------------------------------" << std::endl;

  while (1) {
    /** Create the query **/
    // Read in query from the command line
    string query_string;
    std::cout << "\nPlease enter the index encoded code of an European Country: ";
    getline(cin, query_string);
    std::cout << "Looking for the Capital of " << query_string << "th country in db" << std::endl;
    std::cout << "This may take few minutes ... " << std::endl;
    
    HELIB_NTIMER_START(timer_TotalQuery);

    HELIB_NTIMER_START(timer_EncryptQuery);
    helib::Ptxt<helib::BGV> query_ptxt(context);
    long position = stol(query_string);
    query_ptxt.at(position) = 1;
    helib::Ctxt query(public_key);
    public_key.Encrypt(query, query_ptxt);
    HELIB_NTIMER_STOP(timer_EncryptQuery);

    /************ Perform the database search ************/

    HELIB_NTIMER_START(timer_QuerySearch);
    std::cout << "Searching ..." << std::endl;
    helib::Ctxt res(public_key);
    for (helib::Ctxt& value : database) {
      helib::Ctxt tmp = value;
      tmp *= query;
      res += tmp;
      rotate(query, 1);
      cout << query.capacity() << endl;
    }
    HELIB_NTIMER_STOP(timer_QuerySearch);

    /************ Decrypt and print result ************/

    HELIB_NTIMER_START(timer_DecryptQueryResult);
    helib::Ptxt<helib::BGV> plaintext_result(context);
    secret_key.Decrypt(plaintext_result, res);
    HELIB_NTIMER_STOP(timer_DecryptQueryResult);

    

    // Convert from ASCII to a string
    string string_result;
    for (long i = 0; i < plaintext_result.size(); ++i) {
      long ch = static_cast<long>(plaintext_result[i]);
      if (!ch) continue;
      string_result.push_back(static_cast<long>(plaintext_result[i]));
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