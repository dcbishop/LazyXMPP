#ifndef LAZYXMPP_LAZYXMPP_HPP_
#define LAZYXMPP_LAZYXMPP_HPP_

#include <set>
using namespace std;


#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

using namespace boost::asio;
using boost::asio::ip::tcp;
using boost::shared_ptr;

#include "../Main/UserDB.hpp"
#include "../Main/LazyXMPPConnection.hpp"

typedef set<LazyXMPPConnection*> Connections;


class LazyXMPP {
   public:
      LazyXMPP(int port=5222, bool enableIPv6=true, bool enableIPv4=true);
      ~LazyXMPP();

      inline string getServerHostname() { return hostname_; }
      inline void setServerHostname(string hostname) { hostname_ = hostname; }

      void WriteJid(const string& jid, const char* data, const int& size);

      bool isPlainAuthEnabled() { return enableRegistration_; }
      bool isAnonymousAuthEnabled() { return enableRegistration_; }
      bool isTLSEnabled() { return enableTLS_; }
      bool isRegistrationEnabled() { return enableRegistration_; }
      bool isUnsecureAuthEnabled() { return enableUnsecureAuth_; } // True if accepts plain auth/registeration over unencrytped stream

   friend class LazyXMPPConnection;
   
   private:
      void StartAccepting_(); // Bind the accept handler
      void AcceptHandler_(LazyXMPPConnectionPtr session, const boost::system::error_code& error);
      void addConnection_(LazyXMPPConnection* connection) { connections_mutex_.lock(); connections_ .insert(connection); connections_mutex_.unlock();}
      void removeConnection_(LazyXMPPConnection* connection) { connections_mutex_.lock(); connections_ .erase(connection); connections_mutex_.unlock();}
      UserDB* getUserDB() { return &userdb; }

      UserDB userdb;

      const int port_;
      boost::asio::io_service io_service_;
      tcp::acceptor* acceptor4_;
      tcp::acceptor* acceptor6_;
      string hostname_;
      shared_ptr<boost::thread> thread_;
      
      Connections connections_;
      boost::mutex connections_mutex_;
      
      bool enableIPv6_;
      bool enableIPv4_;
      bool isDualStack_;
      
      bool enableTLS_;
      bool enableRegistration_;
      bool enablePlainAuth_;
      bool enableUnsecureAuth_;
      bool enableAnonymousAuth_;

};

#endif /* LAZYXMPP_LAZYXMPP_HPP_ */

