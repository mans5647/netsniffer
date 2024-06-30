#include "httpparser.h"
#include <QObject>
#include <QDebug>
#include "httprequest.h"

HttpParser::HttpParser(const char *text, size_t len)
{
    llhttp_settings_init(&settings);
    llhttp_init(&parser, HTTP_BOTH, &settings);
    data.assign(text, text + len);
    error = llhttp_errno::HPE_OK;
    _Type = HttpMessageType::Chunk;
    parser.data = this;
    settings.on_message_begin = onMessageBegin;
    settings.on_header_field =  onHeaderName;
    settings.on_header_value =  onHeaderValue;
    settings.on_url =           onUrl;
    settings.on_version =       onVersion;
    settings.on_body =          onBody;
}

llhttp_errno_t HttpParser::Parse()
{
    error = llhttp_execute(&parser, data.constData(), data.size());
    setType((llhttp_type_t)llhttp_get_type(&parser));
    setMethod((llhttp_method)llhttp_get_method(&parser));
    return error;
}

bool HttpParser::hasError()
{
    return (error != llhttp_errno::HPE_OK) ? false : true;
}

const char *HttpParser::getError() const
{
    static QByteArray textual_error;
    textual_error.clear();
    textual_error.append(llhttp_errno_name(error));
    textual_error.append(": ");
    textual_error.append(parser.reason);
    return textual_error.constData();
}

const HttpMessageType HttpParser::getType() const
{
    return _Type;
}

const HttpParser::version_t HttpParser::getVersion() const
{
    return version;
}

const QByteArray &HttpParser::getUrl() const
{
    return url;
}

const llhttp_method HttpParser::getMethod() const
{
    return method;
}

const QByteArray &HttpParser::getBody() const
{
    return body;
}

void HttpParser::setType(llhttp_type_t type)
{
    switch (type)
    {
    case HTTP_REQUEST:  _Type = HttpMessageType::Request; break;
    case HTTP_RESPONSE: _Type = HttpMessageType::Response; break;
    default: _Type = HttpMessageType::Chunk;
    }
}

void HttpParser::setVersion(int major, int minor)
{
    version.first = major;
    version.second = minor;
}

void HttpParser::setUrl(const char *url, size_t len)
{
    this->url.assign(url, url + len);
}

void HttpParser::setMethod(llhttp_method method)
{
    this->method = method;
}

void HttpParser::setBody(const QByteArray &body)
{
    this->body = body;
}

llhttp_t *HttpParser::getParser()
{
    return &parser;
}

const HttpParser::headers &HttpParser::getHeaders() const
{
    return m_headers;
}

HttpRequest *HttpParser::constructRequest()
{
    return new HttpRequest();
}

void *HttpParser::constructResponse()
{
    return nullptr;
}

void HttpParser::setName(const char * at, size_t len)
{
    last_name.assign(at, at + len);
}

void HttpParser::setValue(const char * at, size_t len)
{
    last_value.assign(at, at + len);
}

void HttpParser::push_to_map()
{
    m_headers.insert(last_name, last_value);
}


int HttpParser::onMessageBegin(llhttp_t *parser)
{
    return parser->error;
}

int HttpParser::onUrl(llhttp_t *parser, const char *url, size_t len)
{
    HttpParser * _this = (HttpParser*)parser->data;
    _this->setUrl(url, len);
    return parser->error;
}

int HttpParser::onHeaderName(llhttp_t *parser, const char *at, size_t size)
{

    HttpParser * _this = (HttpParser*)parser->data;
    _this->setName(at, size);
    return parser->error;
}

int HttpParser::onHeaderValue(llhttp_t *parser, const char *at, size_t size)
{
    HttpParser * _this = (HttpParser*)parser->data;
    _this->setValue(at, size);
    _this->push_to_map();
    return parser->error;
}

int HttpParser::onVersion(llhttp_t *parser, const char *at, size_t size)
{
    HttpParser * _this = (HttpParser*)parser->data;
    _this->setVersion((int)at[0], (int)at[2]);
    return parser->error;
}

int HttpParser::onBody(llhttp_t *parser, const char *at, size_t size)
{
    HttpParser * _this = (HttpParser*)parser->data;
    _this->setBody(QByteArray(at, size));
    return llhttp_errno::HPE_OK;
}
