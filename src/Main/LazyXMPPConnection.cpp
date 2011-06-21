#include "../Main/LazyXMPPConnection.hpp"

#include <boost/bind.hpp>
#include <xercesc/util/Base64.hpp>

#include "../Main/LazyXMPP.hpp"
#include "../Debug/console.h"

// Some prebaked raw XMPP XML...
static const string XMPP_XML_HEADER_ = "<?xml version=\"1.0\"?>";
static const string XMPP_STREAM_RESPONSE_01 = "<stream:stream from=\"";
static const string XMPP_STREAM_RESPONSE_02 = "\" id=\"";
static const string XMPP_STREAM_RESPONSE_03 = "\" version=\"1.0\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\">";

static const string XMPP_STREAMFEATURES_01 = "<stream:features>";
static const string XMPP_STREAMFEATURES_02 = "</stream:features>";

static const string XMPP_STREAMFEATURES_MECHANISMS_01 = "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">";
static const string XMPP_STREAMFEATURES_MECHANISMS_02 = "<required/></mechanisms>";

static const string XMPP_STREAMFEATURES_MECHANISM_ANONYMOUS = "<mechanism>ANONYMOUS</mechanism>";
static const string XMPP_STREAMFEATURES_MECHANISM_PLAIN = "<mechanism>PLAIN</mechanism>";

static const string XMPP_STREAMFEATURES_REGISTER = "<register xmlns='http://jabber.org/features/iq-register'/>";
static const string XMPP_STREAMFEATURES_BIND = "<bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"><required/></bind>";
static const string XMPP_STREAMFEATURES_SESSION = "<session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"><optional/></session>";
static const string XMPP_STREAMFEATURES_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

static const string XMPP_STREAMERROR_INVALIDNAMESPACE = "<?xml version='1.0'?><stream:stream id='' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' xmlns='jabber:client'><stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>";
static const string XMPP_STREAMERROR_NOTAUTHORIZED = "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>";

static const string XMPP_AUTHFAILURE_INVALIDMECHANISM = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>";
static const string XMPP_AUTHFAILURE_MALFORMEDREQUEST = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>";

static const string XMPP_SUCCESS = "<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>";

static const string XMPP_IQRESULT_BIND_01 = "<iq type='result' id='";
static const string XMPP_IQRESULT_BIND_02 = "'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>";
static const string XMPP_IQRESULT_BIND_03 = "</jid></bind></iq>";

static const string XMPP_IQRESULT_SESSION_01 = "<session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"/>";
const static string XMPP_IQRESULT_GETREGISTER = "<query xmlns='jabber:iq:register'><instructions>Choose a username and password for use with this service.</instructions><username/><password/></query>";

static const string XMPP_IQ_01 = "<iq type=\"";
static const string XMPP_IQ_02 = "\" id=\"";
static const string XMPP_IQ_03 = "\" to=\"";
static const string XMPP_IQ_04 = "\" from=\"";
static const string XMPP_IQ_05 = "\">";
static const string XMPP_IQ_CLOSE = "</iq>";

static const string XMPP_ROSTER_RESPONSE_01 = "<query xmlns=\"jabber:iq:roster\">";
static const string XMPP_ROSTER_RESPONSE_02 = "</query>";

static const string XMPP_ITEM_01 = "<item subscription=\"to\" name=\"";
static const string XMPP_ITEM_02 = "\" jid=\"";
static const string XMPP_ITEM_03 = "\">";
static const string XMPP_ITEM_CLOSE = "</item>";
static const string XMPP_GROUP_01 = "<group>";
static const string XMPP_GROUP_CLOSE = "<group>";

static const string XMPP_PRESENCE_01 = "<presence from=\"";
static const string XMPP_PRESENCE_02 = "\" to=\"";
static const string XMPP_PRESENCE_03 = "\" type=\"";
static const string XMPP_PRESENCE_04 = "\"/>";

LazyXMPPConnection::~LazyXMPPConnection() {
   DEBUG_M("Shutting down connection. '%s'", getNodeId().c_str());
   // TODO: Send a XMPP error to the client
   getServer()->removeConnection_(this);
}

/**
 * Writes data to a connection.
 */
void LazyXMPPConnection::Write(const char* data, const int& size) {
   DEBUG_M("WRITE: '%s'", data);
   boost::asio::async_write(socket_, boost::asio::buffer(data, size), boost::bind(&LazyXMPPConnection::WriteHandler_, shared_from_this(), boost::asio::placeholders::error));
}

/**
 * Checks for a type of authorization. If unauthorized sends an error and returns true.
 */
bool LazyXMPPConnection::enforeAuthorization_() {
   if(connection_type_ < 1) {
      Write(XMPP_STREAMERROR_NOTAUTHORIZED.c_str(), XMPP_STREAMERROR_NOTAUTHORIZED.size());
      BindRead_();
      return true;
   }
   return false;
}

/**
 * Decides what to do with a XMPP stanza based on it's type.
 */
void LazyXMPPConnection::Chooser_(const char* tag_name_c, DOMElement* element) {
   static const string stream = "stream:stream";
   static const string starttls = "starttls";
   static const string auth = "auth";
   static const string iq = "iq";
   static const string message = "message";
   static const string presence = "presence";

   // Match a <stream> tag.
   if(stream.compare(tag_name_c) == 0) {
      DEBUG_M("XMPP new stream detected...");
      StreamHandler_(element);
      return;
   }

   // Everything below needs to be in an established stream...   
   if(!isInStream_) {
      DEBUG_M("XMPP recieved out of stream.");
      Write(XMPP_STREAMERROR_INVALIDNAMESPACE.c_str(), XMPP_STREAMERROR_INVALIDNAMESPACE.size());
      BindRead_();
      return;
   }

   if(starttls.compare(tag_name_c) == 0) { // Match a <starttls> tag.
      // FIXME: Support TLS
      DEBUG_M("Client attempted to start a TLS stream. We don't support that.");
      static const string ihatesecurity = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>";
      connection_close_ = true;
      Write(ihatesecurity.c_str(), ihatesecurity.size());
      return;
   } else if(auth.compare(tag_name_c) == 0) { // Match an <auth> tag.
      DEBUG_M("Auth recieved...");  
      AuthHandler_(element);
      return;
   } 

   if(iq.compare(tag_name_c) == 0) { // Match <iq> tag.
      IqHandler_(element);
      return;
   } 

   // Everything below needs to be authorized.
   if(enforeAuthorization_()) {
      return;
   }

   if (message.compare(tag_name_c) == 0) {
      MessageHandler_(element);
   } else if (presence.compare(tag_name_c) == 0) {
      PresenceHandler_(element);
   } else {
      DEBUG_M("Unknown XMPP stanza... '%s'", tag_name_c);
   }
}

/**
 * The ASIO write handler.
 */
void LazyXMPPConnection::WriteHandler_(const boost::system::error_code& error) {
   DEBUG_M("Write handler fired...");
   if(!error && !connection_close_) { // If theres no error and we arn't closing this connection, bind another read.
      BindRead_();
   } else if(error) {
      DEBUG_M("Write error...");
   } else {
      DEBUG_M("Connection closed...");
   }
}

/**
 * Parses the data read from socket into XML.
 */
// TODO: Put the XML parsing things somewhere else as static rather than create new ones every request.
void LazyXMPPConnection::Process_(const int size) {
   XMLByte* data_xml_ = reinterpret_cast<XMLByte*>(data_);
   InputSource* in = new MemBufInputSource(data_xml_, size, "xmppstanza", false);

   XercesDOMParser *parser  = new XercesDOMParser();
   ErrorHandler* errHandler = (ErrorHandler*) new HandlerBase();
   parser->setErrorHandler(errHandler);
   
   // We check this here due to the way LazyXMPP parses XML (ie the bad way).
   // This will only work if the closing stream element is by itself.
   static const string endstream = "</stream:stream>";
   if(size > (int)endstream.size()) {
      if(endstream.compare(0, endstream.size(), data_, endstream.size()) == 0) {
         DEBUG_M("End of stream detected...");
         connection_close_ = true;
         return;
      }
   }
   
   try {
      parser->parse(*in); // Parse the recieved XML
   } catch (const XMLException& toCatch) {
      char* message = XMLString::transcode(toCatch.getMessage());
      ERROR("XMPP parsing exception: %s", message);
      // TODO: Send a valid XMPP error message
      XMLString::release(&message);
   } catch (const DOMException& toCatch) {
      char* message = XMLString::transcode(toCatch.msg);
      ERROR("XMPP parsing exception: %s", message);
      // TODO: Send a valid XMPP error message
      XMLString::release(&message);
   } catch(const SAXParseException& toCatch) {
      // This error is to be expected as XMPP is a stream and doesn't close all tags (notabale <stream> ones)...
      /*char* message = XMLString::transcode(toCatch.getMessage());
      ERROR("XMPP parsing exception: %s", message);
      XMLString::release(&message);*/
   }
   catch (...) {
      ERROR("XMPP parsing, unexpected exception...");
      // TODO: Send a valid XMPP error message
   }
   
   //TODO: Handle multiple XMPP elements.
   
   DOMDocument* xmlDoc = parser->getDocument();
   DOMElement* elementRoot = xmlDoc->getDocumentElement();
   if(!elementRoot) {
      // This is expected as there are <?xml> headers.
      //ERROR("Empty XML document...");
   } else {
      const XMLCh* tag_name = elementRoot->getTagName();
      char* tag_name_c = XMLString::transcode(tag_name);

      DEBUG_M("Tag name '%s'...", tag_name_c);
      Chooser_(tag_name_c, elementRoot);

      XMLString::release(&tag_name_c);
   }

   delete in;
   delete parser;
   delete errHandler;
}

/**
 * Binds ASIO handler for reading data.
 */
void LazyXMPPConnection::BindRead_() {
   DEBUG_M("Bind read handler.");      
   socket_.async_read_some(boost::asio::buffer(data_, max_length_), boost::bind(&LazyXMPPConnection::ReadHandler_, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
};

/**
 * The ASIO read handler.
 */
void LazyXMPPConnection::ReadHandler_(const boost::system::error_code& error, size_t bytes) {
   DEBUG_M("Read handler fired, read %d bytes.", bytes);

   // Check for read error
   try {
      if (error == boost::asio::error::eof) {
      DEBUG_M("Clean connection close...");
      return;
   
      } else if(error) {
         throw boost::system::system_error(error);
      }
   } catch (std::exception& e) {
       ERROR("%s", e.what());
       return; // TODO: Write XMPP error message here
   }

   // Null terminate.
   data_[bytes] = '\0';

   // Strip off trailing newlines to help with logging/debugging.
   if(data_[bytes-1] == '\n') {
      data_[bytes-1] = '\0';
   }

   if(!error) {
      DEBUG_M("READ: '%s'", data_);
      Process_(bytes);
      BindRead_();
   } else {
      ERROR("Read error");
   }
}

/**
 * Handles a request to open an XMPP stream.
 */
void LazyXMPPConnection::StreamHandler_(const DOMElement* element) {
   // FIXME:
   // Check to see if 'to' is actually the server.
   // Check to see if IP banned (although maybe ip bans should be a the socket level, although here we can send a message)
   // Check there isn't too many streams already, etc...
   // Maybe keep track of the streams & ids?
   string response = XMPP_XML_HEADER_ + generateStreamResponse_(generateRandomId_()) + generateStreamFeatures_();
   isInStream_ = true;
   Write(response.c_str(), response.size());
}

/**
 * Generates a stream request response XMPP stanza.
 */
string LazyXMPPConnection::generateStreamResponse_(const string& streamid) const {
   return XMPP_STREAM_RESPONSE_01 + getServer()->getServerHostname() + XMPP_STREAM_RESPONSE_02 + streamid + XMPP_STREAM_RESPONSE_03;
}

/**
 * Generates a random id number (based on a UUID).
 */
string LazyXMPPConnection::generateRandomId_() const {
   uuid_t uuid;
   char uuid_c[37];
   uuid_generate(uuid);
   uuid_unparse(uuid, uuid_c);
   return uuid_c;
}

/**
 * Generate a stream features XMPP stanza.
 */
string LazyXMPPConnection::generateStreamFeatures_() const {
   return XMPP_STREAMFEATURES_01 + generateStreamFeaturesTLS_() + generateStreamFeaturesMechanisms_() + generateStreamFeaturesCompression_() + generateStreamFeaturesBind_() + generateStreamFeaturesSession_() + generateStreamFeaturesRegister_() + XMPP_STREAMFEATURES_02;
}

/**
 * Generates a TLS stream feature entry.
 */
string LazyXMPPConnection::generateStreamFeaturesTLS_() const {
   // FIXME: Support TLS...
   if(!getServer()->isTLSEnabled()) {
      return "";
   }

   return XMPP_STREAMFEATURES_STARTTLS;
}

/**
 * Generates a serialized list of authentication mechanisms as a stream feature entry.
 */
string LazyXMPPConnection::generateStreamFeaturesMechanisms_() const {
   // FIXME: Support secure logins...
   
   // Don't offer mechanisms if we are already logged in.
   if(connection_type_ > 0) {
      return "";
   }
   return XMPP_STREAMFEATURES_MECHANISMS_01 + XMPP_STREAMFEATURES_MECHANISM_ANONYMOUS + XMPP_STREAMFEATURES_MECHANISM_PLAIN +  XMPP_STREAMFEATURES_MECHANISMS_02;
}

/**
 * Generates a serialized compression stream feature entry.
 */
string LazyXMPPConnection::generateStreamFeaturesCompression_() const {
   // FIXME: Support compression...
   return "";
}

/**
 * Generates a serialized bind stream feature entry.
 */
string LazyXMPPConnection::generateStreamFeaturesBind_() const {
   // If we have authenticated but not yet bound a resource...
   if(connection_type_ > 0 && !isBound_) {
      return XMPP_STREAMFEATURES_BIND;
   }
   return "";
}

/**
 * Generates a serialized session stream feature entry.
 */
string LazyXMPPConnection::generateStreamFeaturesSession_() const { 
   if(connection_type_ > 0 && !isBound_) {
      return XMPP_STREAMFEATURES_SESSION;
   }
   return "";
}

string LazyXMPPConnection::generateStreamFeaturesRegister_() const {
   if(connection_type_ == 0 && !isBound_ && getServer()->isRegistrationEnabled() ) {
      return XMPP_STREAMFEATURES_REGISTER;
   }
   return "";
}

/**
 * Handles an authentication request.
 */
void LazyXMPPConnection::AuthHandler_(const DOMElement* element) {
   string auth_mechanism = getDOMAttribute_(element, "mechanism");
   
   if(auth_mechanism.compare("PLAIN") == 0) {
      DEBUG_M("Recieved plain auth.");
      AuthPlainHandler_(element);
   } else if(auth_mechanism.compare("ANONYMOUS") == 0) {
      DEBUG_M("Recieved anonymous auth.");
      setNodeId_(generateRandomId_());
      if(getNickname().empty()) {
         setNickname_(getNodeId());
      }
      connection_type_ = ANONYMOUS;
      Write(XMPP_SUCCESS.c_str(), XMPP_SUCCESS.size());
   } else {
      DEBUG_M("Recieved unknown auth.");

      connection_close_ = true;
      Write(XMPP_AUTHFAILURE_INVALIDMECHANISM.c_str(), XMPP_AUTHFAILURE_INVALIDMECHANISM.size());
   }
}

/**
 * Handles using an insecure plain auth.
 */
void LazyXMPPConnection::AuthPlainHandler_(const DOMElement* element) {

      // Decode the base 64
      const XMLCh* encoded_data_x = element->getTextContent();
      XMLSize_t decoded_length = 0;
      XMLByte* decoded_data_x = Base64::decodeToXMLByte(encoded_data_x, &decoded_length);
      if (!decoded_data_x || decoded_length < 1 || decoded_data_x[0] != 0) {
         DEBUG_M("Failed to decode base64...");
         Write(XMPP_AUTHFAILURE_MALFORMEDREQUEST.c_str(), XMPP_AUTHFAILURE_MALFORMEDREQUEST.size());
         return;
      }

      char* nodeid_start = (char*)&decoded_data_x[1];
      unsigned int nodeid_length = strnlen(nodeid_start, decoded_length-1);
      if(nodeid_length >= decoded_length-1) {
         DEBUG_M("Could not detect end of nodeid. Missing terminator character?");
         Write(XMPP_AUTHFAILURE_MALFORMEDREQUEST.c_str(), XMPP_AUTHFAILURE_MALFORMEDREQUEST.size());
         //XMLString::release(&decoded_data_x);
         return;
      }
      
      // The password is seperated by a null byte. Check for it.
      if(nodeid_start[nodeid_length] != '\0' || nodeid_length < 1) {
         DEBUG_M("No null character after nodeid...");
         Write(XMPP_AUTHFAILURE_MALFORMEDREQUEST.c_str(), XMPP_AUTHFAILURE_MALFORMEDREQUEST.size());
         return;
      }

      char nodeid[nodeid_length+1];
      strncpy(nodeid, nodeid_start, nodeid_length);      
      nodeid[nodeid_length] = '\0';

      int passbegin = nodeid_length+2;
      int password_length = decoded_length-passbegin;
      char password[password_length+1];
      strncpy(password, nodeid_start+nodeid_length+1, password_length);
      password[password_length] = '\0';
      DEBUG_M("finalsize: %d", password_length+nodeid_length+2);

      if(password_length+nodeid_length+2 != decoded_length) {
         // Decoded datasize doesn't match extracted nodeid/password size. Weirdness.
         DEBUG_M("Size mismatch");
         Write(XMPP_AUTHFAILURE_MALFORMEDREQUEST.c_str(), XMPP_AUTHFAILURE_MALFORMEDREQUEST.size());
      }

      // TODO: How do you release these in xerces3...
      //XMLString::release(&decoded_data_x);

      // TODO checkpassword or something...
      /*static const string badauthm = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>";
      connection_close_ = true;
      Write(badauthm.c_str(), badauthm.size());*/

      // Set the node id (the bit befoure the @ in a JID). Also set the displayed nick name if there isn't one already.
      setNodeId_(nodeid);
      if(getNickname().empty()) {
         setNickname_(getNodeId());
      }

      // Set that this connection is authenticated and send a sucess response.
      connection_type_ = AUTHENTICATED;      
      Write(XMPP_SUCCESS.c_str(), XMPP_SUCCESS.size());
      LOG("XMPP authentication sucessfull for %s. Logged in as '%s'.", getAddress().c_str(), getNodeId().c_str());
      DEBUG_M("Authentication sucessfull.");
}

// IQ Stuff here

/**
 * Handles an iq request.
 */
void LazyXMPPConnection::IqHandler_(const DOMElement* element) {
   string id = getDOMAttribute_(element, "id");
   string iq_type = getDOMAttribute_(element, "type");
   
   // See what type of iq request this is...
   if(iq_type.compare("set") == 0) {
      DEBUG_M("Recieved iq set.");
      IqSetHandler_(id, element);
   } if(iq_type.compare("get") == 0) {
      IqGetHandler_(id, element);
   } else if(iq_type.compare("result") == 0) {
      // Do nothing...
   } else {
      //TODO: Send XMPP error...
      
      DEBUG_M("Recieved unknown iq.");
      //static const string badauthm = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>";
      //connection_close_ = true;
      //Write(badauthm.c_str(), badauthm.size());
   }

}

/**
 * Handles an iq set request.
 */
void LazyXMPPConnection::IqSetHandler_(const string& id, const DOMElement* element) {
   int length = element->getChildElementCount();
   if(length != 1) {
      DEBUG_M("Unexpected number of iq child elements.");
      // TODO: ERROR
      return;
   }

   DOMElement* child = element->getFirstElementChild();

   char *tag_name = XMLString::transcode(child->getTagName());
   string tag_name_s = tag_name;
   XMLString::release(&tag_name);

   DEBUG_M("IQ set '%s'", tag_name_s.c_str());

   if(tag_name_s.compare("query") == 0) {
      IqSetQueryHandler_(id, child);
      return;
   }

   if(enforeAuthorization_()) {
      return;
   }

   if(tag_name_s.compare("bind") == 0) {
      IqSetBind_(id, child);
   } else if(tag_name_s.compare("session") == 0) {
      IqSetSession_(id);
   }
   //TODO: No match, send error...
}

/**
 * Adds a player to everyones roster.
 */
// TODO: Rather than a roster system, use MUC.
// TODO: This doesn't seem to work...
void LazyXMPPConnection::addToRosters_() {
   DEBUG_M("Entered function...");
   getServer()->connections_mutex_.lock();
   for (Connections::iterator it=getServer()->connections_.begin() ; it != getServer()->connections_.end(); it++ ) {
      string to = (*it)->getJid();
      string forward = generateIqHeader_("set", generateRandomId_(), to, getFullJid()) + XMPP_ROSTER_RESPONSE_01 + generateRosterItem_(getNickname(), getFullJid(), "") + XMPP_ROSTER_RESPONSE_02 + XMPP_IQ_CLOSE;
      
      (*it)->Write(forward.c_str(), forward.size());
   }
   getServer()->connections_mutex_.unlock();
}

/**
 * Handles a bind resource request.
 */
void LazyXMPPConnection::IqSetBind_(const string& id, const DOMElement* bind) {
   // TODO: Don't allow more than 1 bind per connection (unless XMPP does?)
   DEBUG_M("IqSetBind_.");
   static const string bind_s = "bind";
   
   const DOMElement* resourceElement = getSingleDOMElementByTagName_(bind, "resource");
     
   string resource;
   if(!resourceElement) {
      resource = generateRandomId_();
   } else {
      char *tag_name = XMLString::transcode(resourceElement->getTextContent());
      DEBUG_M("Requested resource '%s'", resource.c_str());
      resource = tag_name;
   }
   
   setResource_(resource);
   isBound_ = true;
   string response = generateIqResultBind_(id, resource);
   Write(response.c_str(), response.size());
   addToRosters_();
}

/**
 * Generates a serialized iq bind response stanza.
 */
//TODO: Add an option to use /> to close rather than > for one line responses.
string LazyXMPPConnection::generateIqResultBind_(const string& id, const string& resource) const {
   return XMPP_IQRESULT_BIND_01 + id + XMPP_IQRESULT_BIND_02 + getNodeId() + "@" + getServer()->getServerHostname() + "/" + resource + XMPP_IQRESULT_BIND_03;
}

/**
 * Handles an iq set session. This is apparently not really necessary but XMPP clients might expect the functionality.
 */
void LazyXMPPConnection::IqSetSession_(const string& id) {
   DEBUG_M("Entering function...");
   isSession_ = true;
   string response = generateIqHeader_("result", id, getFullJid()) + XMPP_IQRESULT_SESSION_01 + XMPP_IQ_CLOSE;
   Write(response.c_str(), response.size());
}

/**
 * Gets the ip address of the connection.
 */
string LazyXMPPConnection::getAddress() const { 
   return socket_.remote_endpoint().address().to_string();
}

/**
 * Returns the connections Jabber ID (excluding the resource part).
 */
string LazyXMPPConnection::getJid() const { 
   return getNodeId() + "@" + getServer()->getServerHostname();
}

/**
 * Returns the conenctions Jabber ID, including the resource part.
 */
string LazyXMPPConnection::getFullJid() const { 
   return getJid() + "/" + getResource();
}

/**
 * Handles an iq get request.
 */
void LazyXMPPConnection::IqGetHandler_(const string& id, const DOMElement* element) {
   DEBUG_M("Entering function...");
   int length = element->getChildElementCount();
   if(length != 1) {
      DEBUG_M("Unexpected number of iq child elements.");
      // TODO: ERROR
      return;
   }

   DOMElement* child = element->getFirstElementChild();

   char *tag_name = XMLString::transcode(child->getTagName());
   string tag_name_s = tag_name;
   XMLString::release(&tag_name);

   DEBUG_M("IQ get '%s'", tag_name_s.c_str());

   // Allow unauthorized query requests for 'register'.
   if(tag_name_s.compare("query") == 0) {
      IqGetQueryHandler_(id, child);
      return;
   }

   // Everything below needs to be authorized.
   if(enforeAuthorization_()) {
      return;
   }

   if(tag_name_s.compare("bind") == 0) {
      // TODO
      DEBUG_M("Unhandled iq get bind.");
   } else if(tag_name_s.compare("session") == 0) {
      // TODO
      DEBUG_M("Unhandled iq get session.");
   }  else if(tag_name_s.compare("ping") == 0) {
      string response = generateIqHeader_("result", id, getFullJid(), getServer()->getServerHostname()) + XMPP_IQ_CLOSE;
      Write(response.c_str(), response.size());
   }
   
   // TODO: Error
}

void LazyXMPPConnection::IqSetQueryHandler_(const string& id, const DOMElement* element) {
   string query_type_s = getDOMAttribute_(element, "xmlns");

   if(query_type_s.compare("jabber:iq:register") == 0) {
      IqSetQueryRegister_(id, element);
   } 
   // TODO: Error
}

void LazyXMPPConnection::IqSetQueryRegister_(const string& id, const DOMElement* element) {
   // TODO: process register information
   string errormsg = generateServiceUnavailableError_(id, element);
   Write(errormsg.c_str(), errormsg.size());
}


/**
 * Handles an iq query request.
 */
void LazyXMPPConnection::IqGetQueryHandler_(const string& id, const DOMElement* element) {
   DEBUG_M("Entering function...");
   
   string query_type_s = getDOMAttribute_(element, "xmlns");
   DEBUG_M("Query type '%s'...", query_type_s.c_str() );

   if(query_type_s.compare("jabber:iq:register") == 0) {
      IqGetQueryRegister_(id, element);
      return;
   } 

   // Everything below needs to be authorized.
   if(enforeAuthorization_()) {
      return;
   }
   
   if(query_type_s.compare("jabber:iq:roster") == 0) {
      IqGetQueryRosterHandler_(id, element);
   } else if(query_type_s.compare("http://jabber.org/protocol/disco#items") == 0) {
      IqGetQueryDiscoItems_(id, element);
   } else if(query_type_s.compare("http://jabber.org/protocol/disco#info") == 0) {
      IqGetQueryDiscoInfo_(id, element);
   } else {
      string response = generateServiceUnavailableError_(id, element);
      Write(response.c_str(), response.size());
   }
}


string LazyXMPPConnection::generateServiceUnavailableError_(const string& id, const DOMElement* element) const {
   return generateIqHeader_("error", id, getFullJid(), getServer()->getServerHostname()) + "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" + XMPP_IQ_CLOSE;
}

/**
 * Handles a service discovery info query.
 */
// TODO
void LazyXMPPConnection::IqGetQueryDiscoItems_(const string& id, const DOMElement* element) {
   string response = generateIqHeader_("result", id, getFullJid(), getServer()->getServerHostname()) + "<query xmlns=\"http://jabber.org/protocol/disco#items\"></query></iq>";
   Write(response.c_str(), response.size()); 
}

/**
 * Handles a service discovery info query.
 */
// TODO
void LazyXMPPConnection::IqGetQueryDiscoInfo_(const string& id, const DOMElement* element) {
   string response = generateIqHeader_("result", id, getFullJid(), getServer()->getServerHostname()) + "<query xmlns=\"http://jabber.org/protocol/disco#items\"></query></iq>";
   Write(response.c_str(), response.size()); 
}

/**
 * Generates a serialzed <iq> header for a XMPP stanza.
 */
string LazyXMPPConnection::generateIqHeader_(const string& type, const string& id, const string& to, const string& from) const {
   string header = XMPP_IQ_01 + type + XMPP_IQ_02 + id;
   if(!to.empty()) {
      header.append(XMPP_IQ_03 + to);
   }
   if(!from.empty()) {
      header.append(XMPP_IQ_04 + from);
   }
   header.append(XMPP_IQ_05);
   return header;
}

/**
 * Handles a iq roster get request.
 */
void LazyXMPPConnection::IqGetQueryRosterHandler_(const string& id, const DOMElement* element) {
   DEBUG_M("Entering function...");
   string response = generateIqHeader_("result", id, getJid()) + XMPP_ROSTER_RESPONSE_01 + generateRosterItems_() + XMPP_ROSTER_RESPONSE_02 + XMPP_IQ_CLOSE;
   Write(response.c_str(), response.size());
}

/**
 * Generates all the items to go into a XMPP roster stanza.
 */
string LazyXMPPConnection::generateRosterItems_() const {
   DEBUG_M("Entering function...");
   // TODO
   string roster;
   getServer()->connections_mutex_.lock();
   
   // TODO: This adds everyone to everyone's roster. Switching to MUC chat makes more sense.
   for (Connections::iterator it=getServer()->connections_.begin() ; it != getServer()->connections_.end(); it++ ) {
      string nickname = (*it)->getNickname();
      string jid = (*it)->getJid();
      roster.append(generateRosterItem_(nickname, jid, ""));
   }
   
   getServer()->connections_mutex_.unlock();
   return roster;
}

/**
 * Generates a seialized roster item for a XMPP stanza.
 */
string LazyXMPPConnection::generateRosterItem_(const string& name, const string& jid, const string& group = "") const {
   string result = XMPP_ITEM_01 + name + XMPP_ITEM_02 + jid + XMPP_ITEM_03;
   if(!group.empty()) {
      result.append(XMPP_GROUP_01 + group + XMPP_GROUP_CLOSE);
   }
   result.append(XMPP_ITEM_CLOSE);
   return result;
}

/**
 * Handles a request for registeration information.
 */
void LazyXMPPConnection::IqGetQueryRegister_(const string& id, const DOMElement* element) {
   if(getServer()->isRegistrationEnabled() && connection_type_ == NOT_AUTHENTICATED) {
      string response = generateIqHeader_("result", id, getFullJid()) + XMPP_IQRESULT_GETREGISTER  + XMPP_IQ_CLOSE;
      Write(response.c_str(), response.size());
      return;
   }

   string errormsg = generateServiceUnavailableError_(id, element);
   Write(errormsg.c_str(), errormsg.size());
   return;
   
}

/**
 * A Xerces-c cheat code to avoid having to do all the transcoding stuff every time. Returns a std::string with the atribute value.
 */
// TODO: It's probably better to replace the raw strings with a bunch of static, pretranscoded xerces XMLCh* ones to avoid transcodes at runtime.
string LazyXMPPConnection::getDOMAttribute_(const DOMElement* element, const string& attribute_name) const {
   XMLCh* attribute_name_x = XMLString::transcode(attribute_name.c_str());
   char *attribute_name_c = XMLString::transcode(element->getAttribute(attribute_name_x));
   string attribute_name_s = attribute_name_c;
   XMLString::release(&attribute_name_x);
   XMLString::release(&attribute_name_c);
   return attribute_name_s;
}

/**
 * Another Xerces-c cheat code to avoid having to do a dynamic cast or situations where the wrong number of elements are contained.
 */
DOMElement* LazyXMPPConnection::getSingleDOMElementByTagName_(const DOMElement* element, const string& tag) const {
   XMLCh* tag_x = XMLString::transcode(tag.c_str());
   DOMNodeList* children = element->getElementsByTagName(tag_x);
   XMLString::release(&tag_x);

   if(children->getLength() < 1) {
      return NULL;
   }

   DOMNode* child_n = children->item(0);
   if(!child_n) {
      return NULL;
   }

   DOMElement* child_e = dynamic_cast<xercesc::DOMElement*>(child_n);
   return child_e;
}

/**
 * Xerces cheat. Gets the text inbetween open and close tags as a string.
 */
string LazyXMPPConnection::getTextContent_(const DOMElement* element) const {
   const XMLCh* data_x = element->getTextContent();
   char* data_c = XMLString::transcode(data_x);
   string result = data_c;
   XMLString::release(&data_c);
   return result;
}

/**
 * Serializes Xerces DOM data into plain text.
 */
string LazyXMPPConnection::StringifyNode_(const DOMNode* node) const {
   XMLCh tempStr[max_length_];
   XMLString::transcode("LS", tempStr, max_length_-1);
   DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(tempStr);
   DOMLSSerializer* theSerializer = ((DOMImplementationLS*)impl)->createLSSerializer();
   XMLCh* data_x = theSerializer->writeToString(node);
   char* data_c = XMLString::transcode(data_x);
   string result = data_c;
   XMLString::release(&data_c);
   XMLString::release(&data_x);
   theSerializer->release();
   return result;
}

/**
 * Xerces cheat. Sets an attribute on an element from strings.
 */
void LazyXMPPConnection::setDOMAttribute_(DOMElement* element, const string& attribute, const string& value) const {
   XMLCh* value_x = XMLString::transcode(value.c_str());
   XMLCh* attribute_x = XMLString::transcode(attribute.c_str());
   element->setAttribute(attribute_x, value_x);
   XMLString::release(&value_x);
   XMLString::release(&attribute_x);
}

/**
 * Handles a XMPP <message>.
 */
void LazyXMPPConnection::MessageHandler_(DOMElement* element) {
   // This function is way to heavy, all it really needs to do if forward the messages with an added 'from' but by now it's already been parsed and needs to be serialized, this entire thing should be done with SAX.
   //TODO
   string to = getDOMAttribute_(element, "to");
   //string from = getDOMAttribute_(element, "from");
   //string type = getDOMAttribute_(element, "type");
   
   DOMElement* body_e = getSingleDOMElementByTagName_(element, "body");
   if(!body_e) {
      DEBUG_M("Message with no body...");
      return;
   }

   // Stamp on the 'from' attribute.
   setDOMAttribute_(element, "from", getFullJid());
   
   // Convert the Xerces dom back into text and send it to the recipient.
   string forward = StringifyNode_(element);  
   getServer()->WriteJid(to, forward.c_str(), forward.size());
   DEBUG_M("Forward '%s'", forward.c_str());
        
   return;
}

/**
 * Generates a serialized <presence> message.
 */
string LazyXMPPConnection::generatePresence_(const string& to, const string& type = "") const {
   string response = XMPP_PRESENCE_01 + getFullJid() + XMPP_PRESENCE_02 + to;
   if(!type.empty()) {
      response.append(XMPP_PRESENCE_03 + type);
   }
   response.append(XMPP_PRESENCE_04);
   return response;
}

/**
 * Handles a XMPP <presence>
 */
void LazyXMPPConnection::PresenceHandler_(DOMElement* element) {
   string type = getDOMAttribute_(element, "type");
   string to = getDOMAttribute_(element, "to");
 
   // Initial presence... Send probes to everyone.
   if(to.empty() && type.empty()) {
      getServer()->connections_mutex_.lock();
      for (Connections::iterator it=getServer()->connections_.begin() ; it != getServer()->connections_.end(); it++ ) {
         
         string jid = (*it)->getJid();
         string presence = generatePresence_(jid, "probe");
         (*it)->Write(presence.c_str(), presence.size());
      }
      getServer()->connections_mutex_.unlock();
   }
   
   // Forward normal presences...
   if(!to.empty()) {
      setDOMAttribute_(element, "from", getFullJid());
      string forward = StringifyNode_(element);
      getServer()->WriteJid(to, forward.c_str(), forward.size());
   }

   // Normal broadcast...
   if(to.empty()) {
      setDOMAttribute_(element, "from", getFullJid());
      getServer()->connections_mutex_.lock();
      for (Connections::iterator it=getServer()->connections_.begin() ; it != getServer()->connections_.end(); it++ ) {
         string jid = (*it)->getJid();
         setDOMAttribute_(element, "to", jid);
         string forward = StringifyNode_(element);
         (*it)->Write(forward.c_str(), forward.size());
      }
      getServer()->connections_mutex_.unlock();
   }
}
