#include "../Main/LazyXMPPConnection.hpp"

#include <boost/bind.hpp>
#include <xercesc/util/Base64.hpp>

#include "../Main/LazyXMPP.hpp"
#include "../Debug/console.h"

// Some prebaked raw XMMP XML...
static const string XMPP_XML_HEADER_ = "<?xml version=\"1.0\"?>";
static const string XMPP_STREAM_RESPONSE_01 = "<stream:stream from=\"";
static const string XMPP_STREAM_RESPONSE_02 = "\" id=\"";
static const string XMPP_STREAM_RESPONSE_03 = "\" version=\"1.0\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\">";

static const string XMPP_STREAMFEATURES_01 = "<stream:features>";
static const string XMPP_STREAMFEATURES_02 = "</stream:features>";

static const string XMPP_STREAMFEATURES_MECHANISMS_01 = "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>ANONYMOUS</mechanism><mechanism>PLAIN</mechanism><required/></mechanisms>";

static const string XMPP_STREAMFEATURES_BIND = "<bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"><required/></bind>";
static const string XMPP_STREAMFEATURES_SESSION = "<session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"><optional/></session>";

static const string XMPP_SUCCESS = "<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>";

static const string XMPP_IQRESULT_BIND_01 = "<iq type='result' id='";
static const string XMPP_IQRESULT_BIND_02 = "'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>";
static const string XMPP_IQRESULT_BIND_03 = "</jid></bind></iq>";

static const string XMPP_IQRESULT_SESSION_01 = "<session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"/>";

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
   server_->removeConnection_(this);
}

void LazyXMPPConnection::Write(const char* data, const int& size) {
   DEBUG_M("WRITE: '%s'", data);
   boost::asio::async_write(socket_, boost::asio::buffer(data, size), boost::bind(&LazyXMPPConnection::WriteHandler, shared_from_this(), boost::asio::placeholders::error));
}

void LazyXMPPConnection::Chooser(const char* tag_name_c, DOMElement* element) {
   static const string stream = "stream:stream";
   static const string starttls = "starttls";
   static const string auth = "auth";
   static const string iq = "iq";
   static const string message = "message";
   static const string presence = "presence";

   if(stream.compare(tag_name_c) == 0) {
      DEBUG_M("XMPP new stream detected...");
      StreamHandler(element);
      return;
   }

   // Everything below needs to be in an established stream...   
   if(!isInStream_) {
      DEBUG_M("XMPP recieved out of stream.");
      BindRead();
      return;
   }

   /*if(endstream.compare(tag_name_c) == 0) {
      DEBUG_M("XMPP stream closed...");
      connection_close_ = true;
      return;
   }*/

   // TODO: Check for a close stream and take approproiate action

   if(starttls.compare(tag_name_c) == 0) {
      // FIXME: Support TLS
      DEBUG_M("Client attempted to start a TLS stream. We don't support that.");
      static const string ihatesecurity = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>";
      connection_close_ = true;
      Write(ihatesecurity.c_str(), ihatesecurity.size());
      return;
   } else if(auth.compare(tag_name_c) == 0) {
      DEBUG_M("Auth recieved...");  
      AuthHandler(element);
      return;
   } 

   // Everything below needs to be authorized
   if(connection_type_ < 1) {
      BindRead();
      return;
   }

   if(iq.compare(tag_name_c) == 0) {
      IqHandler(element);
   } else if (message.compare(tag_name_c) == 0) {
      MessageHandler(element);
   } else if (presence.compare(tag_name_c) == 0) {
      PresenceHandler(element);
   } else {
      DEBUG_M("Unknown XMPP stanza... '%s'", tag_name_c);
   }
}

void LazyXMPPConnection::WriteHandler(const boost::system::error_code& error) {
   DEBUG_M("Write handler fired...");
   if(!error && !connection_close_) {
      BindRead();
   } else if(error) {
      DEBUG_M("Write error...");
   } else {
      DEBUG_M("Connection closed...");
   }
}

void LazyXMPPConnection::Process(const int size) {
   XMLByte* data_xml_ = reinterpret_cast<XMLByte*>(data_);
   InputSource* in = new MemBufInputSource(data_xml_, size, "xmppstanza", false);

   XercesDOMParser *parser  = new XercesDOMParser();
   ErrorHandler* errHandler = (ErrorHandler*) new HandlerBase();
   parser->setErrorHandler(errHandler);
   
   static const string endstream = "</stream:stream>";
   if(size > (int)endstream.size()) {
      if(endstream.compare(0, endstream.size(), data_, endstream.size()) == 0) {
         DEBUG_M("End of stream detected...");
         connection_close_ = true;
         return;
      }
   }
   
   try {
      parser->parse(*in);
   } catch (const XMLException& toCatch) {
      char* message = XMLString::transcode(toCatch.getMessage());
      ERROR("XMPP parsing exception: %s", message);
      XMLString::release(&message);
   } catch (const DOMException& toCatch) {
      char* message = XMLString::transcode(toCatch.msg);
      ERROR("XMPP parsing exception: %s", message);
      XMLString::release(&message);
   } catch(const SAXParseException& toCatch) {
      // This error is to be expected as XMPP is a stream and doesn't close tags...
      /*char* message = XMLString::transcode(toCatch.getMessage());
      ERROR("XMPP parsing exception: %s", message);
      XMLString::release(&message);*/
   }
   catch (...) {
      ERROR("XMPP parsing, unexpected exception...");
   }
   
   DOMDocument* xmlDoc = parser->getDocument();
   DOMElement* elementRoot = xmlDoc->getDocumentElement();
   if(!elementRoot) {
      // This is expected as there are XML headers.
      //ERROR("Empty XML document...");
   } else {
      const XMLCh* tag_name = elementRoot->getTagName();
      char* tag_name_c = XMLString::transcode(tag_name);

      DEBUG_M("Tag name '%s'...", tag_name_c);
      Chooser(tag_name_c, elementRoot);

      XMLString::release(&tag_name_c);
   }

   delete in;
   delete parser;
   delete errHandler;
}

void LazyXMPPConnection::BindRead() {
   DEBUG_M("Bind read handler.");      
   socket_.async_read_some(boost::asio::buffer(data_, max_length_), boost::bind(&LazyXMPPConnection::ReadHandler, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
};

void LazyXMPPConnection::ReadHandler(const boost::system::error_code& error, size_t bytes) {
   DEBUG_M("Read handler fired, read %d bytes.", bytes);

   // Null terminate
   data_[bytes] = '\0';

   // Strip off trailing newlines to help with logging/debugging.
   if(data_[bytes-1] == '\n') {
      data_[bytes-1] = '\0';
   }
 
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
      DEBUG_M("READ: '%s'", data_);
      Process(bytes);
      BindRead();
   } else {
      ERROR("Read error");
   }
}

// XMPP Stream stuff
void LazyXMPPConnection::StreamHandler(const DOMElement* element) {
   // FIXME:
   // Check to see if 'to' is actually the server.
   // Check to see if IP banned (although ip bans should be a the socket level), Too many streams already, etc...
   // Maybe keep track of the streams & ids?
   string response = XMPP_XML_HEADER_ + generateStreamResponse(generateRandomId()) + generateStreamFeatures();
   isInStream_ = true;
   Write(response.c_str(), response.size());
}

string LazyXMPPConnection::generateStreamResponse(const string& streamid) const {
   return XMPP_STREAM_RESPONSE_01 + server_->getServerHostname() + XMPP_STREAM_RESPONSE_02 + streamid + XMPP_STREAM_RESPONSE_03;
}

string LazyXMPPConnection::generateRandomId() const {
   uuid_t uuid;
   char uuid_c[37];
   uuid_generate(uuid);
   uuid_unparse(uuid, uuid_c);
   return uuid_c;
}

string LazyXMPPConnection::generateStreamFeatures() const {
   return XMPP_STREAMFEATURES_01 + generateStreamFeaturesTLS() + generateStreamFeaturesMechanisms() + generateStreamFeaturesCompression() + generateStreamFeaturesBind() + generateStreamFeaturesSession() + XMPP_STREAMFEATURES_02;
}

string LazyXMPPConnection::generateStreamFeaturesTLS() const {
   // FIXME: Support TLS...
   return "";
}

string LazyXMPPConnection::generateStreamFeaturesMechanisms() const {
   // FIXME: Support secure logins...
   
   // Don't offer mechanisms if we are already logged in.
   if(connection_type_ > 0) {
      return "";
   }
   return XMPP_STREAMFEATURES_MECHANISMS_01;
}

string LazyXMPPConnection::generateStreamFeaturesCompression() const {
   // FIXME: Support compression...
   return "";
}

string LazyXMPPConnection::generateStreamFeaturesBind() const {
   // If we have authenticated but not yet bound a resource...
   if(connection_type_ > 0 && !isBound_) {
      return XMPP_STREAMFEATURES_BIND;
   }
   return "";
}

// Session is generally not needed
string LazyXMPPConnection::generateStreamFeaturesSession() const { 
   if(connection_type_ > 0 && !isBound_) {
      return XMPP_STREAMFEATURES_SESSION;
   }
   return "";
}

// Auth stuff
void LazyXMPPConnection::AuthHandler(const DOMElement* element) {
   string auth_mechanism = getDOMAttribute(element, "mechanism");
   
   if(auth_mechanism.compare("PLAIN") == 0) {
      DEBUG_M("Recieved plain auth.");
      AuthPlainHandler(element);
   } else if(auth_mechanism.compare("ANONYMOUS") == 0) {
      DEBUG_M("Recieved anonymous auth.");
      setNodeId(generateRandomId());
      if(getNickname().empty()) {
         setNickname(getNodeId());
      }
      connection_type_ = ANONYMOUS;
      Write(XMPP_SUCCESS.c_str(), XMPP_SUCCESS.size());
   } else {
      DEBUG_M("Recieved unknown auth.");
      static const string badauthm = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>";
      connection_close_ = true;
      Write(badauthm.c_str(), badauthm.size());
   }
}

void LazyXMPPConnection::AuthPlainHandler(const DOMElement* element) {
      const XMLCh* encoded_data_x = element->getTextContent();
      XMLSize_t decoded_length = 0;
      XMLByte* decoded_data_x = Base64::decodeToXMLByte(encoded_data_x, &decoded_length);
      if (!decoded_data_x || decoded_length < 1 || decoded_data_x[0] != 0) {
         DEBUG_M("Failed to decode base64...");
         //TODO handle this...
         return;
      }
              
      char* nodeid_start = (char*)&decoded_data_x[1];
      unsigned int nodeid_length = strnlen(nodeid_start, decoded_length-1);
      
      if(nodeid_length >= decoded_length-1) {
         DEBUG_M("Could not detect end of nodeid. Missing terminator character?");
         // TODO: Weird data, abort propperly
         // TODO: How do you release these in xerces3...
         //XMLString::release(&decoded_data_x);
         return;
      }
      if(nodeid_start[nodeid_length] != '\0' || nodeid_length < 1) {
         DEBUG_M("No null character after nodeid...");
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
      }

      // TODO: How do you release these in xerces3...
      //XMLString::release(&decoded_data_x);

      // TODO checkpassword or something...
      /*static const string badauthm = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>";
      connection_close_ = true;
      Write(badauthm.c_str(), badauthm.size());*/

      setNodeId(nodeid);
      if(getNickname().empty()) {
         setNickname(getNodeId());
      }
      
      connection_type_ = AUTHENTICATED;      
      Write(XMPP_SUCCESS.c_str(), XMPP_SUCCESS.size());

      DEBUG_M("Authentication sucessfull.");
}

// IQ Stuff
void LazyXMPPConnection::IqHandler(const DOMElement* element) {
   string id = getDOMAttribute(element, "id");
   string iq_type = getDOMAttribute(element, "type");
   
   if(iq_type.compare("set") == 0) {
      DEBUG_M("Recieved iq set.");
      IqSetHandler(id, element);
   } if(iq_type.compare("get") == 0) {
      IqGetHandler(id, element);
   } else {
      //TODO
      
      DEBUG_M("Recieved unknown iq.");
      //static const string badauthm = "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>";
      //connection_close_ = true;
      //Write(badauthm.c_str(), badauthm.size());
   }

}

void DebugPrintAndKillThing(const XMLCh *debugname) {
   char* debug = XMLString::transcode(debugname);
   DEBUG_M("debug: '%s'", debug);
   XMLString::release(&debug);
}
   

void LazyXMPPConnection::IqSetHandler(const string& id, const DOMElement* element) {
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

   if(tag_name_s.compare("bind") == 0) {
      IqSetBind(id, child);
   } else if(tag_name_s.compare("session") == 0) {
      IqSetSession(id);
   } else if(tag_name_s.compare("query") == 0) {
      // TODO
   }
}

void LazyXMPPConnection::addToRosters() {
   DEBUG_M("Entered function...");
   server_->connections_mutex_.lock();
   for (Connections::iterator it=server_->connections_.begin() ; it != server_->connections_.end(); it++ ) {
      string to = (*it)->getJid();
      string forward = generateIqHeader("set", generateRandomId(), to, getFullJid()) + XMPP_ROSTER_RESPONSE_01 + generateRosterItem(getNickname(), getFullJid(), "") + XMPP_ROSTER_RESPONSE_02 + XMPP_IQ_CLOSE;
      
      (*it)->Write(forward.c_str(), forward.size());
   }
   server_->connections_mutex_.unlock();
}

void LazyXMPPConnection::IqSetBind(const string& id, const DOMElement* bind) {
   DEBUG_M("IqSetBind.");
   static const string bind_s = "bind";
   
   const DOMElement* resourceElement = getSingleDOMElementByTagName(bind, "resource");
     
   string resource;
   if(!resourceElement) {
      resource = generateRandomId();
   } else {
      char *tag_name = XMLString::transcode(resourceElement->getTextContent());
      DEBUG_M("Requested resource '%s'", resource.c_str());
      resource = tag_name;
   }
   
   setResource(resource);
   isBound_ = true;
   string response = generateIqResultBind(id, resource);
   Write(response.c_str(), response.size());
   addToRosters();
}

string LazyXMPPConnection::generateIqResultBind(const string& id, const string& resource) const {
   return XMPP_IQRESULT_BIND_01 + id + XMPP_IQRESULT_BIND_02 + getNodeId() + "@" + server_->getServerHostname() + "/" + resource + XMPP_IQRESULT_BIND_03;
}

void LazyXMPPConnection::IqSetSession(const string& id) {
   DEBUG_M("Entering function...");
   isSession_ = true;
   string response = generateIqHeader("result", id, getFullJid()) + XMPP_IQRESULT_SESSION_01 + XMPP_IQ_CLOSE;
   Write(response.c_str(), response.size());
}

string LazyXMPPConnection::getFullJid() const { 
   return getJid() + "/" + getResource();
}

string LazyXMPPConnection::getJid() const { 
   return getNodeId() + "@" + server_->getServerHostname();
}

void LazyXMPPConnection::IqGetHandler(const string& id, const DOMElement* element) {
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

   if(tag_name_s.compare("bind") == 0) {
      // TODO
   } else if(tag_name_s.compare("session") == 0) {
      // TODO
   } else if(tag_name_s.compare("query") == 0) {
      IqGetQueryHandler(id, child);
   }
   
   // TODO: Error
}

void LazyXMPPConnection::IqGetQueryHandler(const string& id, const DOMElement* element) {
   DEBUG_M("Entering function...");
   
   string query_type_s = getDOMAttribute(element, "xmlns");
   
   if(query_type_s.compare("jabber:iq:roster") == 0) {
      IqGetQueryRosterHandler(id, element);
   } else if(query_type_s.compare("http://jabber.org/protocol/disco#items") == 0) {
      IqGetQueryDiscoItems(id, element);
   } else if(query_type_s.compare("http://jabber.org/protocol/disco#info") == 0) {
      IqGetQueryDiscoInfo(id, element);
   } else if(query_type_s.compare("ping") == 0) {
      string response = generateIqHeader("result", id, getFullJid(), server_->getServerHostname()) + XMPP_IQ_CLOSE;
      Write(response.c_str(), response.size());
   } else {
      string response = generateIqHeader("error", id, getFullJid(), server_->getServerHostname()) + "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" + XMPP_IQ_CLOSE;
      Write(response.c_str(), response.size());
   }
}

void LazyXMPPConnection::IqGetQueryDiscoItems(const string& id, const DOMElement* element) {
   string response = generateIqHeader("result", id, getFullJid(), server_->getServerHostname()) + "<query xmlns=\"http://jabber.org/protocol/disco#items\"></query></iq>";
   Write(response.c_str(), response.size()); 
}

void LazyXMPPConnection::IqGetQueryDiscoInfo(const string& id, const DOMElement* element) {
   string response = generateIqHeader("result", id, getFullJid(), server_->getServerHostname()) + "<query xmlns=\"http://jabber.org/protocol/disco#items\"></query></iq>";
   Write(response.c_str(), response.size()); 
}

string LazyXMPPConnection::generateIqHeader(const string& type, const string& id, const string& to, const string& from) const {
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

void LazyXMPPConnection::IqGetQueryRosterHandler(const string& id, const DOMElement* element) {
   DEBUG_M("Entering function...");
   string response = generateIqHeader("result", id, getJid()) + XMPP_ROSTER_RESPONSE_01 + generateRosterItems() + XMPP_ROSTER_RESPONSE_02 + XMPP_IQ_CLOSE;
   Write(response.c_str(), response.size());
}

string LazyXMPPConnection::generateRosterItems() const {
   DEBUG_M("Entering function...");
   // TODO
   string roster;
   server_->connections_mutex_.lock();
   
   for (Connections::iterator it=server_->connections_.begin() ; it != server_->connections_.end(); it++ ) {
      string nickname = (*it)->getNickname();
      string jid = (*it)->getJid();
      roster.append(generateRosterItem(nickname, jid, ""));
   }
   
   server_->connections_mutex_.unlock();
   return roster;
}

string LazyXMPPConnection::generateRosterItem(const string& name, const string& jid, const string& group = "") const {
   string result = XMPP_ITEM_01 + name + XMPP_ITEM_02 + jid + XMPP_ITEM_03;
   if(!group.empty()) {
      result.append(XMPP_GROUP_01 + group + XMPP_GROUP_CLOSE);
   }
   result.append(XMPP_ITEM_CLOSE);
   return result;
}

string LazyXMPPConnection::getDOMAttribute(const DOMElement* element, const string& attribute_name) const {
   XMLCh* attribute_name_x = XMLString::transcode(attribute_name.c_str());
   char *attribute_name_c = XMLString::transcode(element->getAttribute(attribute_name_x));
   string attribute_name_s = attribute_name_c;
   XMLString::release(&attribute_name_x);
   XMLString::release(&attribute_name_c);
   return attribute_name_s;
}

DOMElement* LazyXMPPConnection::getSingleDOMElementByTagName(const DOMElement* element, const string& tag) const {
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

string LazyXMPPConnection::getTextContent(const DOMElement* element) const {
   const XMLCh* data_x = element->getTextContent();
   char* data_c = XMLString::transcode(data_x);
   string result = data_c;
   XMLString::release(&data_c);
   return result;
}

string LazyXMPPConnection::StringifyNode(const DOMNode* node) const {
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

void LazyXMPPConnection::setDOMAttribute(DOMElement* element, const string& attribute, const string& value) const {
   XMLCh* value_x = XMLString::transcode(value.c_str());
   XMLCh* attribute_x = XMLString::transcode(attribute.c_str());
   element->setAttribute(attribute_x, value_x);
   XMLString::release(&value_x);
   XMLString::release(&attribute_x);
}
        
void LazyXMPPConnection::MessageHandler(DOMElement* element) {
   // This function is way to heavy, all it really needs to do if forward the messages with an added 'from' but by now it's already been parsed and needs to be unparsed, this entire thing should be done with SAX.
   //TODO
   string to = getDOMAttribute(element, "to");
   //string from = getDOMAttribute(element, "from");
   //string type = getDOMAttribute(element, "type");
   
   DOMElement* body_e = getSingleDOMElementByTagName(element, "body");
   if(!body_e) {
      DEBUG_M("Message with no body...");
      return;
   }

   setDOMAttribute(element, "from", getFullJid());
   
   string forward = StringifyNode(element);
   DEBUG_M("Forward '%s'", forward.c_str());
   
   server_->WriteJid(to, forward.c_str(), forward.size());
     
   return;
}



/*string LazyXMPPConnection::generateIqHeader(const string& type, const string& id, const string& to, const string& from) const {

}*/
string LazyXMPPConnection::generatePresence(const string& to, const string& type = "") const {
   string response = XMPP_PRESENCE_01 + getFullJid() + XMPP_PRESENCE_02 + to;
   if(!type.empty()) {
      response.append(XMPP_PRESENCE_03 + type);
   }
   response.append(XMPP_PRESENCE_04);
   return response;
}

void LazyXMPPConnection::PresenceHandler(DOMElement* element) {
   string type = getDOMAttribute(element, "type");
   string to = getDOMAttribute(element, "to");
 
   // Initial presence... Send probes to everyone.
   if(to.empty() && type.empty()) {
      server_->connections_mutex_.lock();
      for (Connections::iterator it=server_->connections_.begin() ; it != server_->connections_.end(); it++ ) {
         
         string jid = (*it)->getJid();
         string presence = generatePresence(jid, "probe");
         (*it)->Write(presence.c_str(), presence.size());
      }
      server_->connections_mutex_.unlock();
   }
   
   // Forward normal presences...
   if(!to.empty()) {
      setDOMAttribute(element, "from", getFullJid());
      string forward = StringifyNode(element);
      server_->WriteJid(to, forward.c_str(), forward.size());
   }

   // Normal broadcast...
   if(to.empty()) {
      setDOMAttribute(element, "from", getFullJid());
      server_->connections_mutex_.lock();
      for (Connections::iterator it=server_->connections_.begin() ; it != server_->connections_.end(); it++ ) {
         string jid = (*it)->getJid();
         setDOMAttribute(element, "to", jid);
         string forward = StringifyNode(element);
         (*it)->Write(forward.c_str(), forward.size());
      }
      server_->connections_mutex_.unlock();
   }
}
