#ifndef LAZYXMPP_LAZYXMPP_HPP_
#define LAZYXMPP_LAZYXMPP_HPP_

#include <set>
using namespace std;


#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

using namespace boost::asio;
using boost::asio::ip::tcp;

#include "../Main/LazyXMPPConnection.hpp"

typedef set<LazyXMPPConnection*> Connections;


class LazyXMPP {
   public:
      LazyXMPP(int port=5222, bool enableIPv6=true, bool enableIPv4=true);
      ~LazyXMPP();

      inline string getServerHostname() { return hostname_; }
      inline void setServerHostname(string hostname) { hostname_ = hostname; }

   friend class LazyXMPPConnection;
   
   private:
      void StartAccepting_(); // Bind the accept handler
      void AcceptHandler_(LazyXMPPConnectionPtr session, const boost::system::error_code& error);
      void addConnection_(LazyXMPPConnection* connection) { connections_mutex_.lock(); connections_ .insert(connection); connections_mutex_.unlock();}
      void removeConnection_(LazyXMPPConnection* connection) { connections_mutex_.lock(); connections_ .erase(connection); connections_mutex_.unlock();}
      void WriteJid(const string& jid, const char* data, const int& size);


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

};

#endif /* LAZYXMPP_LAZYXMPP_HPP_ */

