"""Модуль, используемый для разбора и редактирования SIP-сообщений

Часть пакета p2psip, портированная на python3.6
"""
import re

from typing import Any

_debug = False

# Различные типы заголовков: standard (default), address, comma and unstructured
_address = ['contact', 'from', 'record-route', 'refer-to', 'referred-by', 'route', 'to']
_comma = ['allow', 'authorization', 'proxy-authenticate', 'proxy-authorization', 'www-authenticate']
_unstructured = ['call-id', 'cseq', 'date', 'expires', 'max-forwards', 'organization', 'server', 'subject',
                 'timestamp', 'user-agent']
# Сокращенные варианты имен заголовков:
_short = ['allow-events', 'u', 'call-id', 'i', 'contact', 'm', 'content-encoding', 'e', 'content-length', 'l',
          'content-type', 'c', 'event', 'o', 'from', 'f', 'subject', 's', 'supported', 'k', 'to', 't', 'via', 'v']
# Исключение для каноникализации имен заголовков
_exception = {'call-id': 'Call-ID', 'cseq': 'CSeq', 'www-authenticate': 'WWW-Authenticate', 'x-real-ip': 'X-Real-IP'}


def _canon(s: str) -> bool:
    """Метод, возвращающий флаг того, что предоставленная строка соответствует какой-либо каноничной форме заголовка

    :param s: Строка, содержащая заголовок в произвольном регистре
    :return: Флаг, указывающий на то, является ли переданная строка корректным заголовком
    """
    s = s.lower()
    return ((len(s) == 1) and s in _short and _canon(_short[_short.index(s) - 1])) \
        or (s in _exception and _exception[s]) or '-'.join([x.capitalize() for x in s.split('-')])


class URI:
    """Класс, описывающий объект URI с динамическими свойствами

    Артибуты и элементы URI: scheme, user, password, host, port, param[name], header[index]

    :param value: Строка, на основе которой необходимо сгенерировать объект URI
    """
    _syntax = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*):'  # scheme
                         + '(?:(?:(?P<user>[a-zA-Z0-9-_.!~*\'()&=+$,;?/%]+)'  # user
                         + '(?::(?P<password>[^:@;?]+))?)@)?'  # password
                         + '(?:(?:(?P<host>[^;?:]*)(?::(?P<port>[0-9]+))?))'  # host, port
                         + '(?:;(?P<params>[^?]*))?'  # parameters
                         + '(?:[?](?P<headers>.*))?$')  # headers
    _syntax_urn = re.compile(r'^(?P<scheme>urn):(?P<host>[^;?>]+)$')

    def __init__(self, value: str='') -> None:
        if value:
            m = URI._syntax.match(value)
            if m:
                self.scheme, self.user, self.password, self.host, self.port, params, headers = m.groups()
            elif URI._syntax_urn.match(value):
                m = URI._syntax_urn.match(value)
                self.scheme, self.host = m.groups()
                self.user = self.password = self.port = params = headers = None
            else:
                raise ValueError('Invalid URI(' + value + ')')
            if self.scheme == 'tel' and self.user is None:
                self.user, self.host = self.host, None
            self.port = self.port and int(self.port) or None
            self.param = dict(map(lambda k: (k[0], k[2] if k[2] else None),
                                  map(lambda n: n.partition('='), params.split(';')))) if params else {}
            self.header = [nv for nv in headers.split('&')] if headers else []
        else:
            self.scheme = self.user = self.password = self.host = self.port = None
            self.param = {}
            self.header = []

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление URI-объекта

        :return: Строка, собранная из элементов URI-объекта
        """
        user, host = (self.user, self.host) if self.scheme != 'tel' else (None, self.user)
        result = ''
        if self.scheme and host:
            result += self.scheme + ':'
            if user:
                result += user
                if self.password:
                    result += ':' + self.password
                result += '@'
            result += host
            if self.port:
                result += ':' + str(self.port)
            if len(self.param) > 0:
                result += ';' + ';'.join([(n + '=' + v if v is not None else n) for n, v in sorted(self.param.items())])
            if len(self.header) > 0:
                result += '?' + '&'.join(self.header)
        return result

    def dup(self) -> object:
        """Метод, возвращающий дубликат URI-объекта

        :return: Копия URI-объекта, созданная из его строкового представления
        """
        return URI(self.__repr__())

    def __hash__(self) -> int:
        """Магический метод, возвращающий хэш-сумму строкового представления URI-объекта

        :return: Целое число, содержащее хещ-сумму URI-объекта
        """
        return hash(str(self).lower())

    def __cmp__(self, other) -> int:
        """Магический метод, выполняющий сравнение 2-х URI-объектов

        :param other: URI-объект, с которым будет выполняться сравнение
        :return: Результат сравнения строковых представлений URI-объектов
        """
        """Compare two URI objects by comparing their hash values"""
        a = str(self).lower()
        b = str(other).lower()
        if a > b:
            return 1
        elif a < b:
            return -1
        else:
            return 0

    @property
    def host_port(self) -> tuple:
        """Метод, возвращающий комбинацию (хост, порт) для данного URI-объекта

        :return: Кортеж, содержащий Хост и Порт для данного URI-объекта
        """
        """Read-only tuple (host, port) for this uri."""
        return self.host, self.port

    def _ssecure(self, value: str) -> None:
        """Метод, указывающий необходимость использовать защищенный протокол

        :param value: Строка, содержащая протокол, для которого необходимо применить настройку
        """
        if value and self.scheme in ['sip', 'http']:
            self.scheme += 's'

    def _gsecure(self) -> bool:
        """Метод, возвращающий флаг того, используется ли защищенный протокол

        :return: Флаг, содержащий признак того, что используется защищенный протокол
        """
        return True if self.scheme in ['sips', 'https'] else False

    secure = property(fget=_gsecure, fset=_ssecure)


class Address:
    """Класс, описывающий объект адреса с различными свойсвами

    Артибуты: displayName(str), uri(URI)
    Свойства: mustQuote - определяет, должна ли URI-часть обрамляться кавычками при строковом представлении объекта

    :param value: Строка, на основе которой необходимо сгенерировать объект адреса
    """
    _syntax = [re.compile('^(?P<name>[a-zA-Z0-9._+~ \t-]*)<(?P<uri>[^>]+)>'),
               re.compile('^(?:"(?P<name>[^"]+)")[ \t]*<(?P<uri>[^>]+)>'),
               re.compile('^[ \t]*(?P<name>)(?P<uri>[^;]+)')]

    def __init__(self, value: str=None):
        self.displayName = self.uri = None
        self.wildcard = self.mustQuote = False
        if value:
            self.parse(value)

    def parse(self, value: str) -> int:
        """Метод, выполняющий парсинг строкового представления адреса

        :param value: Строка, содержащая в своем составе строковое представление адреса

        :return: Целое число, представляющее длину той части строки, которая совпала с шаблоном адреса и была обработана
        """
        if str(value).startswith('*'):
            self.wildcard = True
            return 1
        else:
            for s in Address._syntax:
                m = s.match(value)
                if m:
                    self.displayName = m.groups()[0].strip()
                    self.uri = URI(m.groups()[1].strip())
                    return m.end()

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление адреса

        :return: Строка, собранная из элементов адреса
        """
        result = ''
        if self.displayName:
            result += '"' + self.displayName + '"'
        if self.uri:
            uri = repr(self.uri)
            if self.mustQuote or self.displayName:
                uri = '<' + uri + '>'
            result += ' ' + uri

        return result

    def dup(self) -> object:
        """Метод, возвращающий дубликат адреса

        :return: Копия объекта адреса, созданная из его строкового представления
        """
        return Address(self.__repr__())

    @property
    def displayable(self) -> str:
        """Метод, возвращающий визуально-читаемое представление Адреса

        :return: Строка содержащая копию первых 25 символов строкового представления объекта адреса
        """
        return self.get_displayable(limit=25)

    def get_displayable(self, limit: int) -> str:
        """Метод, возвращающий представление адреса ограниченной длины

        :param limit: Целое число, содержащее максимальную длину необрезанного сегмента
        :return: Строка, содержащая строковое представление элемента адреса
        """
        name = self.displayName or self.uri and self.uri.user or self.uri and self.uri.host or ''
        return name if len(name) < limit else (name[0:limit - 3] + '...')


class Header:
    """Класс, описывающий объект заголовка с различными свойсвами

    :param value: Строка, на основе которой необходимо сгенерировать объект заголовка
    :param name: Строка, содержащая имя заголовка
    """
    def __init__(self, value: str=None, name: str=None) -> None:
        self.name = name and _canon(name.strip()) or None
        self.value = self._parse(value.strip(), self.name and self.name.lower() or None)

    def _parse(self, value: str, name: str) -> str:
        """Метод, выполняющий парсинг строки на основе которой необходимо сгенерировать заголовок

        :param value: Строка, которую необходимо распарсить
        :param name: Строка, содержащая имя заголовка
        :return: Строка, содержащая основное тело заголовка, без параметров
        """
        if name in _address:  # address header
            addr = Address()
            addr.mustQuote = True
            count = addr.parse(value)
            value, rest = addr, value[count:]
            if rest:
                for k, v in self.parse_params(rest):
                    self.__dict__[k] = v
        elif name not in _comma and name not in _unstructured:  # standard
            value, sep, rest = value.partition(';')
            if rest:
                for k, v in self.parse_params(rest):
                    self.__dict__[k] = v
        if name in _comma:
            self.authMethod, sep, rest = value.strip().partition(' ')
            if rest:
                for k, v in self.parse_params(rest, delimiter=','):
                    self.__dict__[k] = v
        elif name == 'cseq':
            n, sep, self.method = map(lambda x: x.strip(), value.partition(' '))
            self.number = int(n)
            value = n + ' ' + self.method
        return value

    @staticmethod
    def parse_params(rest: str, delimiter: str=';') -> list:
        """Метод-генератор, выполняющий парсинг параметра на основе переданного делителя

        :param rest: Строка, содержащая набор параметров, который необходимо распарсить
        :param delimiter: Символ, служащий разделителем параметров
        :return: Список кортежей, состоящих из пар "имя-знечение" параметров
        """
        try:
            length, index = len(rest), 0
            while index < length:
                sep1 = rest.find('=', index)
                sep2 = rest.find(delimiter, index)
                if sep2 < 0:
                    sep2 = length  # next parameter
                v = ''
                if 0 <= sep1 < sep2:  # parse "a=b;..." or "a=b"
                    n = rest[index:sep1].lower().strip()
                    if rest[sep1+1] == '"':
                        sep1 += 1
                        sep2 = rest.find('"', sep1+1)
                    if sep2 >= 0:
                        v = rest[sep1+1:sep2].strip()
                        index = sep2+1
                    else:
                        v = rest[sep1+1:].strip()
                        index = length
                elif sep1 < 0 or sep1 >= 0 and sep1 > sep2:  # parse "a" or "a;b=c" or ";b"
                    n, index = rest[index:sep2].lower().strip(), sep2+1
                else:
                    break
                if n:
                    yield (n, v)
        except Exception as exc:
            if _debug:
                print('error parsing parameters', exc)

    def __str__(self) -> str:
        """Магический метод, возвращающий строковое представление тела заголовка

        :return: Строка, собранная из элементов тела заголовка
        """
        name = self.name.lower()
        if (name in _comma) or (name in _unstructured):
            rest = ''
        else:
            tag_list = list()
            d = self.__dict__
            for x in d:
                if x not in ('name', 'value', '_viauri'):
                    if re.match(r'^[a-zA-Z0-9\-_.=]*$', str(d[x])):
                        if not d[x]:
                            tag_list.append('%s' % (x,))
                        else:
                            tag_list.append('%s=%s' % (x.lower(), d[x]))
                    else:
                        tag_list.append('%s="%s"' % (x.lower(), d[x]))
            rest = ';'.join(sorted(tag_list))
        return str(self.value) + (rest and (';'+rest) or '')

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление объекта-заголовка

        :return: Строка, собранная из элементов объекта-заголовка
        """
        return self.name + ": " + str(self)

    def dup(self) -> object:
        """Метод, возвращающий дубликат заголовка

        :return: Копия объекта заголовка, созданная из его строкового представления
        """
        return Header(self.__str__(), self.name)

    def __getitem__(self, name: str) -> str:
        """Магический метод, возвращающий значение параметра заголовка по его имени

        :param name: Строка, содержащая имя параметра
        :return: Строка, содержащая значение параметра, или None, если параметр не найден
        """
        return self.__dict__.get(name.lower(), None)

    def __setitem__(self, name: str, value: str) -> None:
        """Магический метод, задающая значение параметра заголовка по переданному имени

        :param name: Строка, содержащая имя параметра
        :param value: Строка, содержащая значение параметра
        """
        self.__dict__[name.lower()] = value

    def __contains__(self, name: str) -> bool:
        """Магический метод, проверяющий присутствие параметра в заголовке

        :param name: Строка, содержащая имя параметра
        :return: Флаг, указывающий наличие/отсутствие параметра в заголовке
        """
        return name.lower() in self.__dict__

    @property
    def via_uri(self) -> object:
        """Метод, возвращающий URI-объект, созданный из заголовка Via

        :return: URI-объект, созданный на основе информации из тела заголовка Via
        """
        if not hasattr(self, '_viaUri'):
            if self.name != 'Via':
                raise ValueError('viaUri available only on Via header')
            proto, addr = self.value.split(' ')
            via_type = proto.split('/')[2].lower()  # udp, tcp, tls
            self._viaUri = URI('sip:' + addr + ';transport=' + via_type)
            if self._viaUri.port is None:
                self._viaUri.port = 5060
            if 'rport' in self:
                try:
                    self._viaUri.port = int(self['rport'])
                except Exception:
                    pass  # probably not an int
            if via_type not in ['tcp', 'sctp', 'tls']:
                if 'maddr' in self:
                    self._viaUri.host = self['maddr']
                elif 'received' in self:
                    self._viaUri.host = self['received']
        return self._viaUri

    @staticmethod
    def create_headers(value: str) -> tuple:
        """Метод, парсящий строку с заголовком и возвращающий кортеж, состоящий из имени и объекта-заголовка (или
        списка объектов-заголовков, если в качестве разделителя в заголовке используется запятая)

        :param value: Строка, содержащая имя заголовка и его тело
        :return: Кортеж, состоящий из имени и объекта-заголовка(-ов)
        """
        name, value = map(str.strip, value.split(':', 1))
        return _canon(name), map(lambda x: Header(x, name), value.split(',') if name.lower() not in _comma else [value])


class Message:
    """Объект SIP-сообщения, имеющий динамические свойства

    Предоставляет регистронезависимый доступ к элементам-заголовкам, методу, URI, коду ответа, описанию ответа,
    протоколу и и телу сообщения.

    :param value: Строка, из которой необходимо сгенерировать сообщение
    """
    # Атрибуты и элементы, не являющиеся заголовками
    _keywords = ('method', 'uri', 'response', 'responsetext', 'protocol', '_body', 'body')

    # Будет обработан только первый встреченый заголовок, последующие вхождения будут игнорироваться
    _single = ('call-id', 'content-disposition', 'content-length', 'content-type', 'cseq', 'date', 'expires', 'event',
               'max-forwards', 'organization', 'refer-to', 'referred-by', 'server', 'session-expires', 'subject',
               'timestamp', 'to', 'user-agent')

    def __init__(self, value: str=None):
        self.method = self.uri = self.response = self.responsetext = self.protocol = self._body = None
        if value:
            self._parse(value)

    # attribute access: use lower-case name, and use container if not found
    def __getattr__(self, name: str) -> Any:
        return self.__getitem__(name)

    def __getattribute__(self, name: str) -> Any:
        return object.__getattribute__(self, name.lower())

    def __setattr__(self, name: str, value: str) -> None:
        object.__setattr__(self, name.lower(), value)

    def __delattr__(self, name: str) -> None:
        object.__delattr__(self, name.lower())

    # container access: use lower-case key in __dict__
    def __getitem__(self, name: str) -> Any:
        return self.__dict__.get(name.lower(), None)

    def __setitem__(self, name: str, value: str) -> None:
        self.__dict__[name.lower()] = value

    def __delitem__(self, name: str) -> None:
        del self.__dict__[name.lower()]

    def __contains__(self, name: str) -> bool:
        return name.lower() in self.__dict__

    def _parse(self, value: str) -> None:
        """Метод, выполняющий разбор строки, содержащей SIP-сообщение

        :param value: Строка, содержащая SIP-сообщение
        """
        index_crlfcrlf, index_lflf = value.find('\r\n\r\n'), value.find('\n\n')
        if index_crlfcrlf >= 0 and index_lflf >= 0:
            if index_crlfcrlf < index_lflf:
                index_lflf = -1
            else:
                index_crlfcrlf = -1
        if index_crlfcrlf >= 0:
            first_headers, body = value[:index_crlfcrlf], value[index_crlfcrlf+4:]
        elif index_lflf >= 0:
            first_headers, body = value[:index_lflf], value[index_lflf+2:]
        else:
            first_headers, body = value, ''  # assume no body
        try:
            first_line, headers = first_headers.split('\n', 1)
        except Exception:
            raise ValueError('No first line found')
        if first_line[-1] == '\r':
            first_line = first_line[:-1]
        a, b, c = first_line.split(' ', 2)
        try:  # try as response
            self.response, self.responsetext, self.protocol = int(b), c, a  # throws error if b is not int.
        except ValueError:  # probably a request
            self.method, self.uri, self.protocol = a, URI(b), c

        h_list = []
        for h in headers.split('\n'):
            if h and h[-1] == '\r':
                h = h[:-1]
            if h and (h[0] == ' ' or h[0] == '\t'):
                if h_list:
                    h_list[-1] += h
            else:
                h_list.append(h)

        for h in h_list:
            try:
                name, values = Header.create_headers(h)
                values = list(values)
                if name not in self:  # doesn't already exist
                    self[name] = values if len(values) > 1 else values[0]
                elif name not in Message._single:  # valid multiple-instance header
                    if not isinstance(self[name], list):
                        self[name] = [self[name]]
                    self[name] += values
            except Exception:
                if _debug:
                    print('error parsing', h)
                continue
        body_len = int(self['Content-Length'].value) if 'Content-Length' in self else 0
        if body:
            self.body = body
        if self.body is not None and body_len != len(body):
            raise ValueError('Invalid content-length %d!=%d' % (body_len, len(body)))
        for h in ['To', 'From', 'CSeq', 'Call-ID']:
            if h not in self:
                raise ValueError('Mandatory header %s missing' % h)

    def __repr__(self) -> Any:
        """Магический метод, возвращающий строковое представление объекта SIP-сообщения

        :return: Строка, собранная из элементов объекта-заголовка
        """
        if self.method is not None:
            m = self.method + ' ' + str(self.uri) + ' ' + self.protocol + '\r\n'
        elif self.response is not None:
            m = self.protocol + ' ' + str(self.response) + ' ' + self.responsetext + '\r\n'
        else:
            return None  # invalid message
        for h in self:
            m += repr(h) + '\r\n'
        m += '\r\n'
        if self.body is not None:
            m += self.body
        return m

    def dup(self) -> Any:
        """Магический метод, возвращающий строковое представление объекта-заголовка

        :return: Строка, собранная из элементов объекта-заголовка
        """
        return Message(self.__repr__())

    def __iter__(self) -> Any:
        """Магический метод, выполняющий итерацию над объектами-заголовками в составе SIP-сообщения

        :return: Объект-итератор над заголовками сообщения
        """
        h = list()
        for n in filter(lambda x: not x.startswith('_') and x not in Message._keywords, self.__dict__):
            h += filter(lambda x: isinstance(x, Header), self[n] if isinstance(self[n], list) else [self[n]])
        return iter(h)

    def first(self, name: str) -> Any:
        """Метод, возвращающий первый найденый объект-заголовок или None

        :param name: Строка, содежащая имя параметра, который требуется вернуть
        :return: Объект-заголовок SIP-сообщения
        """
        result = self[name]
        return isinstance(result, list) and result[0] or result

    def all(self, *args) -> list:
        """Метод, возвращающий список объектов-заголовков по указанным именам

        :param: Строки, содержащие имена заголовков, которые необходимо включить в возвращаемый список
        :return: Список, содержащий объекты-заголовки SIP-сообщения
        """
        args = map(lambda x: x.lower(), args)
        h = list()
        for n in filter(lambda x: x in args and not x.startswith('_') and x not in Message._keywords, self.__dict__):
            h += filter(lambda x: isinstance(x, Header), self[n] if isinstance(self[n], list) else [self[n]])
        return h

    def insert(self, header: Header, append: bool=False) -> None:
        """Метод, выполняющий вставку объекта-заголовка в сообщение

        :param header: Объект-заголовок, который необходимо добавить в сообщение
        :param append: Флаг, указывающий на то, можно ли добавить содержимое добавляемого заголовка в уже существующий
        """
        if header and header.name:
            if header.name not in self:
                self[header.name] = header
            elif isinstance(self[header.name], Header):
                self[header.name] = (append and [self[header.name], header] or [header, self[header.name]])
            else:
                if append:
                    self[header.name].append(header)
                else:
                    self[header.name].insert(0, header)

    def delete(self, name: str, position: int=None) -> None:
        """Метод, удаляющий указанный заголовок целиком или частично

        :param name: Строка, содержащая имя заголовка, которые требуется удалить
        :param position: Целое число, указывающее на позицию удаляемой части заголовка (0 - первая, -1 - последняя)
        """
        if position is None:
            del self[name]  # remove all headers with this name
        else:
            h = self.all(name)  # get all headers
            try:
                del h[position]    # and remove at given position
            except Exception:
                pass       # ignore any error in index
            if len(h) == 0:
                del self[name]
            else:
                self[name] = h[0] if len(h) == 1 else h

    @property
    def body(self) -> str:
        """Метод, возвращающий содержимое тела сообщения

        :return: Строка, содержащая тело сообщения
        """
        return self._body

    @body.setter
    def body(self, value: str) -> None:
        """Метод, обновляющий тело сообщения и связанный с ним тег

        :param value: Строка, содержащая новое тело сообщения
        """
        self._body = value
        self['Content-Length'] = Header('%d' % (value and len(value) or 0), 'Content-Length')

    @staticmethod
    def _populate_message(m: Any, headers: Any=None, content: str=None) -> None:
        """Метод, добавляющий объекты-заголовки и тело сообщения

        :param m: Объект-сообщение, в которое будут добавляться остальные параметры
        :param headers: Список, содержащий объекты-заголовки, которые будут добавляться в сообщение
        :param content: Строка, содержащая тело сообщения, которое будет добавлено
        """
        if headers:
            for h in headers:
                m.insert(h, True)  # append the header instead of overriding
        if content:
            m.body = content
        else:
            m['Content-Length'] = Header('0', 'Content-Length')

    @staticmethod
    def create_request(method: str, uri: str, headers: Any=None, content: str=None) -> Any:
        """Метод, создающий объект-сообщение типа "SIP-запрос" из переданных параметров

        :param method: Строка, содержащая тип создаваемого запроса
        :param uri: URI-объект, который будет включен в создаваемое сообщение
        :param headers: Список, содержащий объекты-заголовки, которые будут добавлены в создаваемое сообщение
        :param content: Строка, содержащая тело сообщения, которое будет добавлено
        :return: Объект-сообщение типа "SIP-запрос", созданный на основе переданных параметров
        """
        m = Message()
        m.method, m.uri, m.protocol = method, URI(uri), 'SIP/2.0'
        Message._populate_message(m, headers, content)
        if m.CSeq is not None and m.CSeq.method != method:
            m.CSeq = Header(str(m.CSeq.number) + ' ' + method, 'CSeq')
        return m

    @staticmethod
    def create_response(response: int, responsetext: str, headers: Any=None, content: str=None, r: Any=None) -> Any:
        """Метод, создающий объект-сообщение типа "SIP-ответ" из переданных параметров

        :param response: Число, содержащее код ответа
        :param responsetext: Строка, содержащая описание кода ответа
        :param headers: Список, содержащий объекты-заголовки, которые будут добавлены в создаваемое сообщение
        :param content: Строка, содержащая тело сообщения, которое будет добавлено
        :param r: Объект-сообщение, который будет использован при генерации ответа
        :return: Объект-сообщение типа "SIP-ответ", созданный на основе переданных параметров
        """
        m = Message()
        m.response, m.responsetext, m.protocol = response, responsetext, 'SIP/2.0'
        if r:
            m.To, m.From, m.CSeq, m['Call-ID'], m.Via = r.To, r.From, r.CSeq, r['Call-ID'], r.Via
            if response == 100:
                m.Timestamp = r.Timestamp
        Message._populate_message(m, headers, content)
        return m

    @property
    def is_final(self) -> bool:
        """Метод, возвращающий признак того, что данный объект-сообщение имеет конечный код ответа

        :return: Флаг, содержащий признак, является ли данное сообщение является финальным ответом
        """
        return self.response and (self.response >= 200)
