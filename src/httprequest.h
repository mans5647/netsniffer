#ifndef HTTPREQUEST_H
#define HTTPREQUEST_H

#include "llhttp.h"
#include <vector>
#include <string>
#include <utility>
#include <QByteArray>
#include <QObject>
#include <unordered_map>

#define VERSION_INVALID -1

class HttpRequest : public QObject
{
    Q_OBJECT
public:

    //using Header = std::pair<QByteArray, QByteArray>; // pair of two strings
    using version_t = std::pair<int, int>;
    using headers_t = std::unordered_map<QByteArray, QByteArray>;
    HttpRequest();
    void AddHeaderName(const char * ptr, size_t len);
    void AddHeaderValue(const char * ptr, size_t len);
    void setBody(const char * data, size_t len);
    void setUrl(const char * url, size_t len);
    void setMethod(llhttp_method method);
    void setVersion(version_t version);

    const headers_t & getHeaders() const;
    const QByteArray & getBody() const;
    const QByteArray & getUrl() const;
    const llhttp_method getMethod() const;
    const version_t & getVersion() const;

private:
    version_t version;  // http version 1.1 or 1.0
    QByteArray body;    // body, if present
    QByteArray url;     // url
    llhttp_method method; // method
    headers_t m_headers; // headers in map
    QByteArray last_name; // name of last header
    QByteArray last_value; // value of last header

    void _push_to_map();
};

#endif // HTTPREQUEST_H
