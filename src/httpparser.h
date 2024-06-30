#ifndef HTTPPARSER_H
#define HTTPPARSER_H

#include "llhttp.h"
#include <vector>
#include <string>
#include <utility>
#include <QByteArray>
#include <QHash>
#include <unordered_map>


class HttpRequest;
class HttpResponse;

enum class HttpMessageType
{
    Request = 1,
    Response = 2,
    Chunk = 3,
};

class HttpParser
{
public:
    using headers = QHash<QByteArray, QByteArray>;
    using version_t = std::pair<int, int>;
    HttpParser(const char * text, size_t len = 0);
    llhttp_errno_t Parse();
    bool hasError();

    const char * getError() const;


    void setType(llhttp_type_t type);
    void setVersion(int major, int minor);
    void setUrl(const char * url, size_t len);
    void setMethod(llhttp_method method);
    void setBody(const QByteArray & body);

    const HttpMessageType getType() const;
    const version_t getVersion() const;
    const QByteArray & getUrl() const;
    const llhttp_method getMethod() const;
    const QByteArray & getBody() const;


    llhttp_t * getParser();
    const headers &getHeaders() const;


    HttpRequest * constructRequest();
    void * constructResponse();

private:
    llhttp_type_t type;
    llhttp_errno error;
    llhttp_method method;
    llhttp_t parser;
    llhttp_settings_t settings;
    QByteArray data;
    QByteArray url;
    QByteArray body;
    QByteArray last_name, last_value;
    headers m_headers; // http headers
    version_t version; // http version
    HttpMessageType _Type;
    void setName(const char * at, size_t len);
    void setValue(const char * at, size_t len);
    void push_to_map();

    static int onMessageBegin(llhttp_t * parser);
    static int onUrl(llhttp_t * parser, const char * url, size_t len);
    static int onHeaderName(llhttp_t * parser, const char * at, size_t size);
    static int onHeaderValue(llhttp_t * parser, const char * at, size_t size);
    static int onVersion(llhttp_t * parser, const char * at, size_t size);
    static int onBody(llhttp_t * parser, const char * at, size_t size);

};

#endif // HTTPPARSER_H
