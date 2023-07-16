#include <string>

std::string getUsername();
std::string getGeneralPassword();
std::string genPassword(const std::string &raw);
// not thread safe
std::string genMD5(const std::string &raw);
