#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

using boost::asio::ip::tcp;
using namespace std;

class LazyXMPPSession: public boost::enable_shared_from_this<LazyXMPPSession> {
   public:
      LazyXMPPSession(boost::asio::io_service& io_service): socket_(io_service) {data_[0] = '\0'; }
      tcp::socket& getSocket() { return socket_; }
      void Start();
      void ReadHandler(const boost::system::error_code& error, size_t bytes);
   private:
      tcp::socket socket_;
      static const int max_length_ = 1024;
      char data_[max_length_+1];
};

typedef boost::shared_ptr<LazyXMPPSession> LazyXMPPSessionPtr;

class LazyXMPP {
   public:
      LazyXMPP(int port=5222);
      ~LazyXMPP();

   private:
      void StartAccepting_(); // Bind the accept handler
      void AcceptHandler_(LazyXMPPSessionPtr session, const boost::system::error_code& error);
      
      int port_;
      boost::asio::io_service io_service_;
      tcp::acceptor* acceptor_;
};


