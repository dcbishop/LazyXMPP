#ifndef LAZYXMPP_USERDB_HPP_
#define LAZYXMPP_USERDB_HPP_

#include <string>
using namespace std;

#include <sqlite3.h>

#include <crypto++/cryptlib.h>
#include <crypto++/sha.h>
#include <crypto++/osrng.h>
#include <crypto++/integer.h>
#include <crypto++/pwdbased.h>
using namespace CryptoPP;

#include "../Debug/console.h"

class UserDB {
   public:
      UserDB();

      ~UserDB();

      bool registerUser(const string& username, const string& password);
      bool isRegistered(const string& username);
      bool verifyPassword(const string& username, const string& password);

   private:
      string findDB_() const;

      string findOrCreateDB_() {
         string dbfile = findDB_();
         return dbfile;
      }

      bool openDB_(const string& database) {
         int result = sqlite3_open(database.c_str(), &db_);
         return result;
      }

      void closeDB_() {
         sqlite3_close(db_);
         db_ = NULL;
      }

      sqlite3 *db_;
      sqlite3_stmt* register_stmt;
      sqlite3_stmt* lookup_stmt;
      sqlite3_stmt* createdb_stmt;

      PKCS5_PBKDF2_HMAC<SHA512> dk;
      AutoSeededRandomPool rng;
      int salt_len_;
      int rounds_;
};

#endif /* LAZYXMPP_USERDB_HPP_ */
