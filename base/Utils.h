#include <string>

const char * getUsername();
std::string getGeneralPassword();
std::string genPassword(const std::string &raw);
std::string genMD5(const std::string &raw);
bool authenticate(const std::string &user, const std::string &pswd); 