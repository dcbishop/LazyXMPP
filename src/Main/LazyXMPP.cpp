#include "../Main/LazyXMPP.hpp"

#include <boost/bind.hpp>

#include "../Debug/console.h"

LazyXMPP::LazyXMPP(int port, bool enableIPv6, bool enableIPv4) : port_(port), enableIPv6_(enableIPv6), enableIPv4_(enableIPv4) {
   LOG("Starting LazyXMPP server.");
   acceptor4_ = NULL;
   acceptor6_ = NULL;

   // TODO: Security!
   enableTLS_ = false;
   enableRegistration_ = true;
   enablePlainAuth_ = true;
   enableUnsecureAuth_ = true;
   enableAnonymousAuth_ = true;
   
   if(!enableIPv6 && !enableIPv4) {
      LOG("You must enable a socket type!");
      return;
   }
   
   if(!enableIPv4) {
      // TODO: Turn ipv6 only option on acceptor if v4 is disabled...
      WARNING("You turned off IPv4 support, please note that dual stack operating systems will still open up an IPv4 socket with the IPv6 one.");
   }
   
   // Setup IPv6/dualstack connection acceptor...
   if(enableIPv6_) {
      try {
         DEBUG_M("New acceptor.");
         DEBUG_M("Starting IPv6 acceptor...");

         // On POSIX compatible systems and Windows starting at Vista, dual stack allows for both IPv4 and IPv6 on the one interface.
         
         acceptor6_ = new tcp::acceptor(io_service_, tcp::endpoint(tcp::v6(), port));
      } catch(exception& e) {
         ERROR("%s. %s", e.what(), SYMBOL_FATAL);
      }
   }
   
   if(acceptor6_) {
      ip::v6_only option;
      acceptor6_->get_option(option);
      isDualStack_ = !option.value();
   }

   // Setup IPv6 connection acceptor...
   if(enableIPv4_) {
      try {
         // If there is no IPv6 socket or the socket doesn't support dual stack with IPv4, bring up a seperate IPv4 socket.
         if(!acceptor6_ || !isDualStack_) {
            acceptor4_ = new tcp::acceptor(io_service_, tcp::endpoint(tcp::v4(), port));
         } else {
            DEBUG_M("Dual stack supported, skipping IPv4 socket...");
         }
      } catch(exception& e) {
         ERROR("%s. %s", e.what(), SYMBOL_FATAL);
      }
   }
   
   try {
      DEBUG_M("Start Accepting");
      StartAccepting_();
      DEBUG_M("io_service running");
      XMLPlatformUtils::Initialize(); // Initilize Xerces...

   } catch(exception& e) {
      ERROR("%s. %s", e.what(), SYMBOL_FATAL);
   }

   try {
      // Thead off the io_service...
      thread_.reset(new boost::thread(boost::bind(&boost::asio::io_service::run, &io_service_)));
      LOG("LazyXMPP server started.");
      thread_->detach();
   } catch (void *e) {
      ERROR("Could not create thread...");
   }  
}

/**
 * Bind ASIO to accept a connection.
 */
void LazyXMPP::StartAccepting_() {
   DEBUG_M("LazyXMPP binding accept handler.");
   
   if(acceptor6_) {
      LazyXMPPConnectionPtr session6(new LazyXMPPConnection(io_service_, this));
      acceptor6_->async_accept(session6->getSocket_(), boost::bind(&LazyXMPP::AcceptHandler_, this, session6, boost::asio::placeholders::error));
   }
   
   if(acceptor4_) {
      LazyXMPPConnectionPtr session4(new LazyXMPPConnection(io_service_, this));
      acceptor4_->async_accept(session4->getSocket_(), boost::bind(&LazyXMPP::AcceptHandler_, this, session4, boost::asio::placeholders::error));
   }
   
   DEBUG_M("bound accept handler.");
}

/**
 * Fires when a new connection is recieved, accepts it.
 */
void LazyXMPP::AcceptHandler_(LazyXMPPConnectionPtr session, const boost::system::error_code& error) {
   DEBUG_M("AcceptHandler fired.");
   if(!error) {
      LOG("Connection from %s.", session->getAddress().c_str());
      // TODO: Block any banned ip addresses.
      session->BindRead_(); // Bind ASIO to start accepting data on this connection
      addConnection_(session.get()); // Add our new connection to the list of connections.
      StartAccepting_();
   } else {
      ERROR("There was an ASIO accept error...");
   }
}

/**
 * Dispatches data to a connection based on it's Jabber ID (either full or normal).
 */
void LazyXMPP::WriteJid(const string& jid, const char* data, const int& size) {
   connections_mutex_.lock();

   for (Connections::iterator it=connections_.begin() ; it != connections_.end(); it++ ) {
      string temp_jid = (*it)->getJid();
      string temp_jid_r = (*it)->getFullJid();
      if((temp_jid.compare(jid) == 0) || (temp_jid_r.compare(jid) == 0)) {
         DEBUG_M("Found target...");
         (*it)->Write(data, size);
      }
   }
   DEBUG_M("Target not found...");
   connections_mutex_.unlock();
}

LazyXMPP::~LazyXMPP() {
   DEBUG_M("io service shutdown.");
   // TODO: Shutdown all the connections...
   delete acceptor4_;
   delete acceptor6_;
   io_service_.stop();
   XMLPlatformUtils::Terminate();
}
