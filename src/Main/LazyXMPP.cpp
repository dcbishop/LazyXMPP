#include "../Main/LazyXMPP.hpp"

#include <boost/bind.hpp>

#include "../Debug/console.h"

LazyXMPP::LazyXMPP(int port) : port_(port) {
   LOG("Starting LazyXMPP server.");
   try {
      DEBUG_M("New acceptor.");
      acceptor_ = new tcp::acceptor(io_service_, tcp::endpoint(tcp::v4(), port));
      DEBUG_M("Start Accepting");
      StartAccepting_();
      DEBUG_M("io_service running");
      XMLPlatformUtils::Initialize(); // Initilize Xerces...

      try {
         thread_.reset(new boost::thread(boost::bind(&boost::asio::io_service::run, &io_service_)));
      } catch (void *e) {
         ERROR("Could not create thread...");
      }
   } catch(exception& e) {
      ERROR("%s. %s", e.what(), SYMBOL_FATAL);
   }
   LOG("LazyXMPP server started.");
   thread_->detach();
}

/**
 * Bind ASIO to accept a connection.
 */
void LazyXMPP::StartAccepting_() {
   DEBUG_M("LazyXMPP binding accept handler.");
   LazyXMPPConnectionPtr session(new LazyXMPPConnection(io_service_, this));
   acceptor_->async_accept(session->getSocket(), boost::bind(&LazyXMPP::AcceptHandler_, this, session, boost::asio::placeholders::error));
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
      session->BindRead(); // Bind ASIO to start accepting data on this connection
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
   io_service_.stop();
   XMLPlatformUtils::Terminate();
}
