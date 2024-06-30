#include "httprequest.h"


HttpRequest::HttpRequest()
{
    version.first = VERSION_INVALID;
    version.second = VERSION_INVALID;
}

void HttpRequest::AddHeaderName(const char *ptr, size_t len)
{
    last_name.assign(ptr, ptr + len);
}

void HttpRequest::AddHeaderValue(const char *ptr, size_t len)
{
    last_value.assign(ptr, ptr + len);
    _push_to_map();
}

void HttpRequest::setBody(const char *data, size_t len)
{
    this->body.assign(data, data + len);
}

void HttpRequest::setUrl(const char *url, size_t len)
{
    this->url.assign(url, url + len);
}

void HttpRequest::setMethod(llhttp_method method)
{
    this->method = method;
}

void HttpRequest::setVersion(version_t version)
{
    this->version.first =   version.first;
    this->version.second =  version.second;
}

const HttpRequest::headers_t &HttpRequest::getHeaders() const
{
    return m_headers;
}

const QByteArray &HttpRequest::getBody() const
{
    return body;
}

const QByteArray &HttpRequest::getUrl() const
{
    return url;
}

const llhttp_method HttpRequest::getMethod() const
{
    return method;
}

const HttpRequest::version_t &HttpRequest::getVersion() const
{
    return version;
}

void HttpRequest::_push_to_map()
{
    m_headers[last_name] = last_value;
}
