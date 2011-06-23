#ifndef LAZYXMPP_LAZYXMPPCONNECTION_HPP_
#define LAZYXMPP_LAZYXMPPCONNECTION_HPP_

#include <uuid/uuid.h>
#include <string>
using namespace std;

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/sax/HandlerBase.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/dom/DOMElement.hpp>
using namespace xercesc;

class LazyXMPP;

class LazyXMPPConnection: public boost::enable_shared_from_this<LazyXMPPConnection> {
   public:
      LazyXMPPConnection(boost::asio::io_service& io_service, LazyXMPP* server):
         socket_(io_service),
         server_(server),
         connection_type_(NOT_AUTHENTICATED),
         connection_close_(false),
         isInStream_(false),
         isBound_(false),
         isSession_(false),
         isEncrypted_(false)
         { data_[0] = '\0'; }
      ~LazyXMPPConnection();

      string getAddress() const; // IP address (maybe IPv6, IPv4 or on dual stack, IPv4 as an IPv6 (::ffff:123.123.123.123)
      string getFullJid() const; // nodeid@serverhostname/resource
      string getJid() const; // nodeid@serverhostname

      string getNodeId() const { return nodeid_; } // Similar to a persistant username (although not the display nickname).
      string getResource() const { return resource_; } // ID of the specific connection (for multiple logins).
      string getNickname() const { return nickname_; } // Displayed nickname.
      
      LazyXMPP* getServer() const { return server_; }
      
      bool isEncrypted() const { return isEncrypted_; }
      
      enum ConnectionType { NOT_AUTHENTICATED, ANONYMOUS, AUTHENTICATED };

   private:
      friend class LazyXMPP;
      tcp::socket& getSocket_() { return socket_; }
      void BindRead_();
      void Write(const char* data, const int& size);

      // ASIO socket handlers...
      void ReadHandler_(const boost::system::error_code& error, size_t bytes);
      void WriteHandler_(const boost::system::error_code& error);

      void Process_(const int size);
      void Chooser_(const char* tagName_c, DOMElement* element);
      bool enforeAuthorization_();

      inline void setNodeId_(const string& nodeid) { nodeid_ = nodeid; }
      inline void setResource_(const string& resource) { resource_ = resource; }
      inline void setNickname_(const string& nickname) { nickname_ = nickname; }

      // Handle XMPP requests...
      void StreamHandler_(const DOMElement* element);
      void AuthHandler_(const DOMElement* element);
      void AuthPlainHandler_(const DOMElement* element);
      void IqHandler_(const DOMElement* element);
      void IqSetHandler_(const string& id, const DOMElement* element);
      inline void IqSetQueryHandler_(const string& id, const DOMElement* element);
      void IqSetBind_(const string& id, const DOMElement* bind);
      void IqSetSession_(const string& id);
      void IqSetQueryRegister_(const string& id, const DOMElement* element);
      inline void IqGetHandler_(const string& id, const DOMElement* element);
      inline void IqGetQueryHandler_(const string& id, const DOMElement* element);
      inline void IqGetQueryRosterHandler_(const string& id, const DOMElement* element);
      void IqGetQueryDiscoItems_(const string& id, const DOMElement* element);
      void IqGetQueryDiscoInfo_(const string& id, const DOMElement* element);
      void IqGetQueryRegister_(const string& id, const DOMElement* element);
      inline void MessageHandler_(DOMElement* element);
      string StringifyNode_(const DOMNode* node) const;
      inline void PresenceHandler_(DOMElement* element);
      inline string generateServiceUnavailableError_(const string& id, const DOMElement* element) const;

      // Functions to generate XMPP stanzas...
      inline string generateStreamResponse_(const string& streamid) const;
      inline string generateRandomId_() const;
      inline string generateStreamFeatures_() const;
      inline string generateStreamFeaturesTLS_() const;
      inline string generateStreamFeaturesMechanisms_() const;
      inline string generateStreamFeaturesCompression_() const;
      inline string generateStreamFeaturesBind_() const;
      inline string generateStreamFeaturesSession_() const;
      inline string generateStreamFeaturesRegister_() const;

      inline string generateIqHeader_(const string& type, const string& id, const string& to = "", const string& from = "", const bool nobody = false) const;
      inline string generateIqResultBind_(const string& id, const string& resource) const;
      inline string generateRosterItems_() const;
      string generateRosterItem_(const string& name, const string& jid, const string& group) const;
      inline string generatePresence_(const string& to, const string& type) const;

      void addToRosters_();

      // Some cheats for Xerces-c
      inline string getDOMAttribute_(const DOMElement* element, const string& attribute_name) const;
      inline void setDOMAttribute_(DOMElement* element, const string& attribute, const string& value) const;
      inline DOMElement* getSingleDOMElementByTagName_(const DOMElement* element, const string& tag) const;
      inline string getTextContent_(const DOMElement* element) const;

      tcp::socket socket_;
      LazyXMPP* server_;
      static const unsigned int buffer_size_ = 8192;
      static const int max_length_ = buffer_size_-1;
      char data_[buffer_size_];

      int connection_type_;
      bool connection_close_;
      bool isInStream_;
      bool isBound_;
      bool isSession_;
      bool isEncrypted_;

      string nodeid_;
      string resource_;
      string nickname_;
};
typedef boost::shared_ptr<LazyXMPPConnection> LazyXMPPConnectionPtr;


#endif /* LAZYXMPP_LAZYXMPPCONNECTION_HPP_ */
