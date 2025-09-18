#ifndef HTTPPARSER_H
#define HTTPPARSER_H

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


#endif // HTTPPARSER_H
