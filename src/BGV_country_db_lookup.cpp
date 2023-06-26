#include <iostream>

#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

// Utility function to print polynomials
void printPoly(NTL::ZZX& poly)
{
  for (int i = NTL::deg(poly); i >= 0; i--) {
    std::cout << poly[i] << "x^" << i;
    if (i > 0)
      std::cout << " + ";
    else
      std::cout << "\n";
  }
}

// Utility function to read <K,V> CSV data from file
std::vector<std::pair<std::string, std::string>> read_csv(std::string filename)
{
  std::vector<std::pair<std::string, std::string>> dataset;
  std::ifstream data_file(filename);

  if (!data_file.is_open())
    throw std::runtime_error(
        "Error: This example failed trying to open the data file: " + filename +
        "\n           Please check this file exists and try again.");

  std::vector<std::string> row;
  std::string line, entry, temp;

  if (data_file.good()) {
    // Read each line of file
    while (std::getline(data_file, line)) {
      row.clear();
      std::stringstream ss(line);
      while (getline(ss, entry, ',')) {
        row.push_back(entry);
      }
      // Add key value pairs to dataset
      dataset.push_back(std::make_pair(row[0], row[1]));
    }
  }

  data_file.close();
  return dataset;
}

int main(int argc, char* argv[])
{
  /************ HElib boiler plate ************/

  // Note: The parameters have been chosen to provide a somewhat
  // faster running time with a non-realistic security level.
  // Do Not use these parameters in real applications.

  // Plaintext prime modulus
  unsigned long p = 131;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 130; // this will give 48 slots
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 1000;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;
  // Size of NTL thread pool (default =1)
  unsigned long nthreads = 1;
  // input database file name
  std::string db_filename = "countries_dataset";
  // debug output (default no debug output)
  bool debug = false;

  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("nthreads", nthreads, "Size of NTL thread pool");
  amap.arg("db_filename",
           db_filename,
           "Qualified name for the database filename");
  amap.toggle().arg("-debug", debug, "Toggle debug output", "");
  amap.parse(argc, argv);
  std::cout << debug<< std::endl;

  // set NTL Thread pool size
  if (nthreads > 1)
    NTL::SetNumThreads(nthreads);

  // std::string fname = "run_" + db_filename + ".txt";
  // std::ofstream out(fname);//ios_base::app
  // std::streambuf *coutbuf = std::cout.rdbuf(); //save old buf
  // std::cout.rdbuf(out.rdbuf()); //redirect cout to out.txt!

  std::cout << "\n*********************************************************";
  std::cout << "\n*           Privacy Preserving Search Example           *";
  std::cout << "\n*           =================================           *";
  std::cout << "\n*                                                       *";
  std::cout << "\n* This is a sample program for education purposes only. *";
  std::cout << "\n* It implements a very simple homomorphic encryption    *";
  std::cout << "\n* based db search algorithm for demonstration purposes. *";
  std::cout << "\n*                                                       *";
  std::cout << "\n*********************************************************";
  std::cout << "\n" << std::endl;

  std::cout << "---Initialising HE Environment ... ";
  // Initialize context
  // This object will hold information about the algebra used for this scheme.
  std::cout << "\nInitializing the Context ... ";
  HELIB_NTIMER_START(timer_Context);
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();
  HELIB_NTIMER_STOP(timer_Context);

  // Secret key management
  std::cout << "\nCreating Secret Key ...";
  HELIB_NTIMER_START(timer_SecKey);
  // Create a secret key associated with the context
  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  HELIB_NTIMER_STOP(timer_SecKey);

  // Compute key-switching matrices that we need
  HELIB_NTIMER_START(timer_SKM);
  helib::addSome1DMatrices(secret_key);
  HELIB_NTIMER_STOP(timer_SKM);

  // Public key management
  // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
  std::cout << "\nCreating Public Key ...";
  HELIB_NTIMER_START(timer_PubKey);
  const helib::PubKey& public_key = secret_key;
  HELIB_NTIMER_STOP(timer_PubKey);

  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = context.getEA();

  // Print the context
  std::cout << std::endl;
  if (debug)
    context.printout();

  // Print the security level
  // Note: This will be negligible to improve performance time.
  std::cout << "\n***Security Level: " << context.securityLevel()
            << " *** Negligible for this example ***" << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "\nNumber of slots: " << nslots << std::endl;

  /************ Read in the database ************/
  db_filename = "../../"+db_filename+".csv";
  std::vector<std::pair<std::string, std::string>> country_db;
  try {
    country_db = read_csv(db_filename);
  } catch (std::runtime_error& e) {
    std::cerr << "\n" << e.what() << std::endl;
    exit(1);
  }

  // Convert strings into numerical vectors
  std::cout << "\n---Initializing the encrypted key,value pair database ("
            << country_db.size() << " entries)...";
  std::cout
      << "\nConverting strings to numeric representation into Ptxt objects ..."
      << std::endl;

  // Generating the Plain text representation of Country DB
  HELIB_NTIMER_START(timer_PtxtCountryDB);
  std::vector<helib::Ptxt<helib::BGV>> k_ptxt;
  std::vector<helib::Ptxt<helib::BGV>> v_ptxt;
  for (const auto& country_capital_pair : country_db) {
    if (debug) {
      std::cout << "\t\tname_addr_pair.first size = "
                << country_capital_pair.first.size() << " ("
                << country_capital_pair.first << ")"
                << "\tname_addr_pair.second size = "
                << country_capital_pair.second.size() << " ("
                << country_capital_pair.second << ")" << std::endl;
    }
    helib::Ptxt<helib::BGV> country(context);
    helib::Ptxt<helib::BGV> capital(context);
    for (long i = 0; i < country_capital_pair.first.size(); ++i)
      country.at(i) = country_capital_pair.first[i];
    for (long i = 0; i < country_capital_pair.second.size(); ++i)
      capital.at(i) = country_capital_pair.second[i];
    k_ptxt.push_back(country);
    v_ptxt.push_back(capital);
  }
  HELIB_NTIMER_STOP(timer_PtxtCountryDB);

  // Encrypt the Country DB
  std::cout << "Encrypting the database..." << std::endl;
  HELIB_NTIMER_START(timer_CtxtCountryDB);
  std::vector<helib::Ctxt> k_ctxt;
  std::vector<helib::Ctxt> v_ctxt;
  for (long i = 0; i < k_ptxt.size(); i++) {
    helib::Ctxt encrypted_country(public_key);
    helib::Ctxt encrypted_capital(public_key);
    public_key.Encrypt(encrypted_country, k_ptxt[i]);
    public_key.Encrypt(encrypted_capital, v_ptxt[i]);
    k_ctxt.push_back(encrypted_country);
    v_ctxt.push_back(encrypted_capital);
  }

  HELIB_NTIMER_STOP(timer_CtxtCountryDB);

  // Print DB Creation Timers
  if (debug) {
    helib::printNamedTimer(std::cout << std::endl, "timer_Context");
    helib::printNamedTimer(std::cout, "timer_Chain");
    helib::printNamedTimer(std::cout, "timer_SecKey");
    helib::printNamedTimer(std::cout, "timer_SKM");
    helib::printNamedTimer(std::cout, "timer_PubKey");
    helib::printNamedTimer(std::cout, "timer_PtxtCountryDB");
    helib::printNamedTimer(std::cout, "timer_CtxtCountryDB");
  }

  std::cout << "\nInitialization Completed - Ready for Queries" << std::endl;
  std::cout << "--------------------------------------------" << std::endl;

  /** Create the query **/

  // Read in query from the command line
  std::string query_string = "Iceland";
  std::cout << "\nPlease enter the name of an European Country: ";
  // std::getline(std::cin, query_string);
  std::cout << "Looking for the Capital of " << query_string << std::endl;
  std::cout << "This may take few minutes ... " << std::endl;

  HELIB_NTIMER_START(timer_TotalQuery);

  HELIB_NTIMER_START(timer_EncryptQuery);
  // Convert query to a numerical vector
  helib::Ptxt<helib::BGV> query_ptxt(context);
  for (long i = 0; i < query_string.size(); ++i)
    query_ptxt[i] = query_string[i];

  // Encrypt the query
  helib::Ctxt query(public_key);
  public_key.Encrypt(query, query_ptxt);
  HELIB_NTIMER_STOP(timer_EncryptQuery);

  /************ Perform the database search ************/

  HELIB_NTIMER_START(timer_QuerySearch);

  for (helib::Ctxt& key : k_ctxt) {
    key -= query;                   //difference
    key.power(p-1);                 //flt
    totalSums(key);                 //totalsum
    key.power(p-1);                 //flt
    key.negate();                   //negate
    key.addConstant(NTL::ZZX(1));   //add 1
    std::cout << "key" << key.isCorrect() << std::endl; //to check if ctxt will be decrypted correctly
  }
  //inner product of two vectors of ctxt.
  //This is simpler than multiplying the E(value) to each intermediate result and adding all of them
  //Because this procedure does lower level multiplications and additions, then does 1 relinearizing at the end
  //so lower overhead
  helib::Ctxt res = helib::innerProduct(k_ctxt, v_ctxt);
  std::cout << "res" << res.isCorrect() << std::endl; //to check if ctxt will be decrypted correctly

  HELIB_NTIMER_STOP(timer_QuerySearch);

  /************ Decrypt and print result ************/

  HELIB_NTIMER_START(timer_DecryptQueryResult);
  helib::Ptxt<helib::BGV> plaintext_result(context);
  // secret_key.Decrypt(plaintext_result, mask);
  secret_key.Decrypt(plaintext_result, res);
  HELIB_NTIMER_STOP(timer_DecryptQueryResult);

  // Convert from ASCII to a string
  std::string string_result;
  for (long i = 0; i < plaintext_result.size(); ++i)
    string_result.push_back(static_cast<long>(plaintext_result[i]));

  HELIB_NTIMER_STOP(timer_TotalQuery);

  // Print DB Query Timers
  if (debug) {
    helib::printNamedTimer(std::cout << std::endl, "timer_EncryptQuery");
    helib::printNamedTimer(std::cout, "timer_QuerySearch");
    helib::printNamedTimer(std::cout, "timer_DecryptQueryResult");
    std::cout << std::endl;
  }

  if (string_result.at(0) == 0x00) {
    string_result =
        "Country name not in the database."
        "\n*** Please make sure to enter the name of a European Country"
        "\n*** with the first letter in upper case.";
  }
  std::cout << "\nQuery result: " << string_result << std::endl;
  helib::printNamedTimer(std::cout, "timer_TotalQuery");

  // std::cout.rdbuf(coutbuf); //reset to standard output again
  // out.close();
  return 0;
}
