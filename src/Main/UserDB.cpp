#include "UserDB.hpp"

#include <boost/filesystem.hpp>
namespace fs=boost::filesystem;

UserDB::UserDB() {
   LOG("Opening user database. SQLite version %s.", sqlite3_libversion());

   // Check for thread safety
   if(!sqlite3_threadsafe()) {
      ERROR("DANGER! DANGER! DANGER! SQLite was *NOT* compiled with SQLITE_THREADSAFE, this could result in db corruption.");
      // TODO: Look at implementing inbuilt fallback mutexes.
   }

   int result;

   db_ = NULL;
   string dbfile = findOrCreateDB_();
   if(dbfile.empty()) {
      ERROR("No database found.");;
   }

   result = openDB_(dbfile);
   if(result != SQLITE_OK) {
      ERROR("Could not open database.");
   }

   string createdb_s = "CREATE TABLE users (username CHAR(25), password CHAR(255), PRIMARY KEY(username), UNIQUE(username));";
   string register_s = "INSERT INTO users (username, password) VALUES (?, ?);";
   string lookup_s = "SELECT * FROM users WHERE username = ?;";
   

   if(sqlite3_prepare_v2(db_, createdb_s.c_str(), -1, &createdb_stmt, NULL) == SQLITE_OK) {
      result = sqlite3_step(createdb_stmt);
      result = sqlite3_finalize(createdb_stmt);
   }

   if(!sqlite3_prepare_v2(db_, register_s.c_str(), register_s.size()+1, &register_stmt, NULL) == SQLITE_OK) {
      ERROR("Failed to create sqlite register statement.");
      closeDB_();
      throw "User database error.";
   }
   
   if(!sqlite3_prepare_v2(db_, lookup_s.c_str(), lookup_s.size()+1, &lookup_stmt, NULL) == SQLITE_OK) {
      ERROR("Failed to create sqlite lookup statement.");
      closeDB_();
      throw "User database error.";
   }
   
}

UserDB::~UserDB() {
   closeDB_();
   sqlite3_finalize(register_stmt);
   sqlite3_finalize(lookup_stmt);
}

string UserDB::findDB_() const {
   fs::path confdir;
   confdir /= getenv("HOME");
   confdir /= "/.config/LazyXMPP/users.db";
   fs::create_directories(confdir.parent_path());

   return confdir.string();
}

bool UserDB::registerUser(const string& username, const string& password) {
   sqlite3_bind_text(register_stmt, 1, username.c_str(), username.size(), SQLITE_TRANSIENT);
   sqlite3_bind_text(register_stmt, 2, password.c_str(), password.size(), SQLITE_TRANSIENT);

   // TODO: Security, Hash and salt password!

   if(sqlite3_step(register_stmt) != SQLITE_DONE) {
      ERROR("Failed to register new user '%s'.", username.c_str());
   }

   sqlite3_reset(register_stmt);
   sqlite3_clear_bindings(register_stmt);
   return false;
}

bool UserDB::isRegistered(const string& username) {
   bool result = false;
   sqlite3_bind_text(lookup_stmt, 1, username.c_str(), username.size(), SQLITE_TRANSIENT);

   if(sqlite3_step(lookup_stmt) == SQLITE_ROW) {
      result = true;
   }

   sqlite3_reset(lookup_stmt);
   sqlite3_clear_bindings(lookup_stmt);
   return result;
}

bool UserDB::verifyPassword(const string& username, const string& password) {
   bool result = false;
   sqlite3_bind_text(lookup_stmt, 1, username.c_str(), username.size(), SQLITE_TRANSIENT);

   if(sqlite3_step(lookup_stmt) == SQLITE_ROW) {
      const char* pass = (char*)sqlite3_column_text(lookup_stmt, 1);
      if(password.compare(pass) == 0) {
         return true; // Password matches the one in database
      }
   }

   sqlite3_reset(lookup_stmt);
   sqlite3_clear_bindings(lookup_stmt);
   return result;
}
