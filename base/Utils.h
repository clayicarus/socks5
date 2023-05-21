#include <string>

std::string getUsername();
std::string getPassword();
// not thread safe
std::string genMD5(const std::string &raw);
