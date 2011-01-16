#include <iostream>
using namespace std;

#include "../Main/Version.hpp"
#include "../Main/LazyXMPP.hpp"
#include "../Debug/console.h"

int main(int argc, char* argv[]) {
   LOG("Starting %s, version %s, built %s...", argv[0], g_git_version.c_str(), g_build_date.c_str());
   
   LazyXMPP xmpp;
   xmpp.setServerHostname("localhost");
   while(true) {
   }
   LOG("Finished.");
   return 0;
}
