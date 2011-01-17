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
      LazyXMPPConnection(boost::asio::io_service& io_service, LazyXMPP* server): socket_(io_service), server_(server), connection_type_(NOT_AUTHENTICATED), connection_close_(false), isInStream_(false), isBound_(false) { data_[0] = '\0'; }
      ~LazyXMPPConnection();
      tcp::socket& getSocket() { return socket_; }
      void BindRead();
      void Process(const int size);
      void Chooser(const char* tagName_c, DOMElement* element);
      void ReadHandler(const boost::system::error_code& error, size_t bytes);
      void Write(const char* data, const int& size);
      void WriteHandler(const boost::system::error_code& error);
      void StreamHandler(const DOMElement* element);
      inline string generateStreamResponse(const string& streamid) const;
      inline string generateRandomId() const;
      inline string generateStreamFeatures() const;
      inline string generateStreamFeaturesTLS() const;
      inline string generateStreamFeaturesMechanisms() const;
      inline string generateStreamFeaturesCompression() const;
      inline string generateStreamFeaturesBind() const;
      inline string generateStreamFeaturesSession() const;
      void AuthHandler(const DOMElement* element);
      void AuthPlainHandler(const DOMElement* element);
      void IqHandler(const DOMElement* element);
      void IqSetHandler(const string& id, const DOMElement* element);
      void IqSetBind(const string& id, const DOMElement* bind);
      void IqSetSession(const string& id);
      inline string generateIqHeader(const string& type, const string& id, const string& to = "", const string& from = "") const;
      inline string generateIqResultBind(const string& id, const string& resource) const;
      inline void IqGetHandler(const string& id, const DOMElement* element);
      inline void IqGetQueryHandler(const string& id, const DOMElement* element);
      inline void IqGetQueryRosterHandler(const string& id, const DOMElement* element);
      inline string generateRosterItems() const;
      string generateRosterItem(const string& name, const string& jid, const string& group) const;
      void IqGetQueryDiscoItems(const string& id, const DOMElement* element);
      void IqGetQueryDiscoInfo(const string& id, const DOMElement* element);
      inline void MessageHandler(DOMElement* element);
      string StringifyNode(const DOMNode* node) const;
      inline void PresenceHandler(DOMElement* element);
      inline string generatePresence(const string& to, const string& type) const;
      string getAddress() const;

      void addToRosters();

      string getFullJid() const;
      string getJid() const;

      string getNodeId() const { return nodeid_; }
      string getResource() const { return resource_; }
      string getNickname() const { return nickname_; }

      inline void setNodeId(const string& nodeid) { nodeid_ = nodeid; }
      inline void setResource(const string& resource) { resource_ = resource; }
      inline void setNickname(const string& nickname) { nickname_ = nickname; }
            
      // Some cheats for Xerces-c
      inline string getDOMAttribute(const DOMElement* element, const string& attribute_name) const;
      inline void setDOMAttribute(DOMElement* element, const string& attribute, const string& value) const;
      inline DOMElement* getSingleDOMElementByTagName(const DOMElement* element, const string& tag) const;
      inline string getTextContent(const DOMElement* element) const;
      
      
      enum ConnectionType { NOT_AUTHENTICATED, ANONYMOUS, AUTHENTICATED };

   private:
      tcp::socket socket_;
      LazyXMPP* server_;
      static const int max_length_ = 1024;
      char data_[max_length_+1];
      int connection_type_;
      bool connection_close_;

      bool isInStream_;
      bool isBound_;
      bool isSession_;
      
      string nodeid_;
      string resource_;
      string nickname_;
};
typedef boost::shared_ptr<LazyXMPPConnection> LazyXMPPConnectionPtr;


#endif /* LAZYXMPP_LAZYXMPPCONNECTION_HPP_ */
