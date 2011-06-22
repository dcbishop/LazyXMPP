#ifndef LAZYXMPP_USERDB_HPP_
#define LAZYXMPP_USERDB_HPP_

#include <string>
using namespace std;

#include <sqlite3.h>

#include "../Debug/console.h"

// TODO: Security, store salted hashed passwords
// TODO: Sanatize all the input!
      
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
         if(dbfile.empty()) {
            // Create DB
         }
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
};

#endif /* LAZYXMPP_USERDB_HPP_ */
