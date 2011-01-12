#include "../Main/LazyXMPP.hpp"

#include "../Debug/console.h"

void LazyXMPPSession::Start() {
   DEBUG_M("Bind read handler.");      
   socket_.async_read_some(boost::asio::buffer(data_, max_length_), boost::bind(&LazyXMPPSession::ReadHandler, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
};

void LazyXMPPSession::ReadHandler(const boost::system::error_code& error, size_t bytes) {
   DEBUG_M("Read handler fired.");
 
   try {
      if (error == boost::asio::error::eof) {
      DEBUG_M("Clean connection close...");
      return;
   
      } else if(error) {
         throw boost::system::system_error(error);
      }
   } catch (std::exception& e) {
       ERROR("%s", e.what());
   }

   if(!error) {
      DEBUG_M("Read %d bytes.", bytes);
      DEBUG_M("'%s'", data_);
      Start();
   } else {
      ERROR("Read error");
   }
}

LazyXMPP::LazyXMPP(int port) : port_(port) {
   LOG("Starting LazyXMPP server.");
   try {
      DEBUG_M("New acceptor.");
      acceptor_ = new tcp::acceptor(io_service_, tcp::endpoint(tcp::v4(), port));
      DEBUG_M("Start Accepting");
      StartAccepting_();
      DEBUG_M("io_service running");
      io_service_.run();
   } catch(exception& e) {
      ERROR("%s. %s", e.what(), SYMBOL_FATAL);
   }
   LOG("LazyXMPP server started.");
}

void LazyXMPP::StartAccepting_() {
   DEBUG_M("LazyXMPP binding accept handler.");
   LazyXMPPSessionPtr session(new LazyXMPPSession(io_service_));
   acceptor_->async_accept(session->getSocket(), boost::bind(&LazyXMPP::AcceptHandler_, this, session, boost::asio::placeholders::error));
   DEBUG_M("bound accept handler.");
}

void LazyXMPP::AcceptHandler_(LazyXMPPSessionPtr session, const boost::system::error_code& error) {
   DEBUG_M("AcceptHandler fired.");
   if(!error) {
      session->Start();
      StartAccepting_();
   } else {
      ERROR("There was an ASIO accept error...");
   }
}

LazyXMPP::~LazyXMPP() {
   DEBUG_M("io service shutdown.");
   io_service_.stop();
   //delete acceptor_;
}
