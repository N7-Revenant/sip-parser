"""Модуль, используемый для разбора и редактирования SDP

Часть пакета p2psip, портированная на python3.6
"""
import time
import socket

from typing import Any, Optional


class _Attributes:
    """Базовый класс, предоставляющий доступ к своим элементам и аттрибутам по имени

    Возвращает None для некорректных имен вместо выбрасывания исключения

    :param **kwargs: Набор параметров, элементы которого будут распакованы и добавлены в объект класса
    """
    def __getattr__(self, name: str) -> Any:
        """Магический метод, возвращающий значение аттрибута объекта класса по его имени

        :param name: Строка, содержащая имя аттрибута
        :return: Объект, содержащий значение аттрбута, или None, если аттрибут с таким именем не найден
        """
        return self.__getitem__(name)

    def __getitem__(self, name: str) -> Any:
        """Магический метод, возвращающий значение элемента объекта класса по его имени

        :param name: Строка, содержащая имя элемента
        :return: Объект, содержащий значение элемента, или None, если элемент с таким именем не найден
        """
        return self.__dict__.get(name, None)

    def __setitem__(self, name: str, value: Any) -> None:
        """Магический метод, задающая значение параметра по переданному имени

        :param name: Строка, содержащая имя параметра
        :param value: Объект, содержащий значение параметра
        """
        self.__dict__[name] = value

    def __contains__(self, name: str) -> bool:
        """Магический метод, проверяющий присутствие параметра в объекте класса

        :param name: Строка, содержащая имя параметра
        :return: Флаг, указывающий наличие/отсутствие параметра в заголовке
        """
        return name in self.__dict__


class Originator(_Attributes):
    """Класс, предоставляющий доступ к аттрибутам поля инициатора сессии ('o=...')

    Доступные аттрибуты:
    - обязательные: username (str), sessionid (long), version (long), nettype (str), addrtype (str), address (str)

    :param value: Строка, которую необходимо разобрать на элементы и преобразовать их в аттрибуты объекта класса
    """

    def __init__(self, value: Optional[str]=None):
        if value:
            self.username, self.sessionid, self.version, self.nettype, self.addrtype, self.address = value.split(' ')
            self.sessionid = int(self.sessionid)
            self.version = int(self.version)
        else:
            hostname = socket.gethostname()
            self.username, self.sessionid, self.version, self.nettype, self.addrtype, self.address = \
                '-', int(time.time()), int(time.time()), 'IN', 'IP4', (
                            hostname.find('.') > 0 and hostname or socket.gethostbyname(hostname))

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление объекта класса

        :return: Строка, собранная из элементов объекта класса
        """
        return ' '.join(map(lambda x: str(x),
                            [self.username, self.sessionid, self.version, self.nettype, self.addrtype, self.address]))


class Connection(_Attributes):
    """Класс, предоставляющий доступ к аттрибутам поля с информацией о соединении ('c=...')

    Доступные аттрибуты:
    - обязательные: nettype (str), addrtype (str), address (str)
    - опциональные: ttl (int), count (int)

    :param value: Строка, которую необходимо разобрать на элементы и преобразовать их в аттрибуты объекта класса
    :param **kwargs: Набор параметров, на основе которого будет создан объект класса в случае отсутствия value
    """
    def __init__(self, value: Optional[str]=None, **kwargs):
        if value:
            self.nettype, self.addrtype, rest = value.split(' ')
            rest = rest.split('/')
            if len(rest) == 1:
                self.address = rest[0]
            elif len(rest) == 2:
                self.address, self.ttl = rest[0], int(rest[1])
            else:
                self.address, self.ttl, self.count = rest[0], int(rest[1]), int(rest[2])
        elif 'address' in kwargs:
            self.address = kwargs.get('address')
            self.nettype = kwargs.get('nettype', 'IN')
            self.addrtype = kwargs.get('addrtype', 'IP4')
            if 'ttl' in kwargs:
                self.ttl = int(kwargs.get('ttl'))
            if 'count' in kwargs:
                self.count = int(kwargs.get('count'))

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление объекта класса

        :return: Строка, собранная из элементов объекта класса
        """
        return self.nettype + ' ' + self.addrtype + ' ' + self.address + (
            '/' + str(self.ttl) if self.ttl else '') + ('/' + str(self.count) if self.count else '')


class Media(_Attributes):
    """Класс, предоставляющий доступ к аттрибутам поля с информацией о медиа ('m=...')

    Доступные аттрибуты:
    - обязательные: media (str), port (int), proto (str), fmt (list)

    :param value: Строка, которую необходимо разобрать на элементы и преобразовать их в аттрибуты объекта класса
    :param **kwargs: Набор параметров, на основе которого будет создан объект класса в случае отсутствия value
    """

    def __init__(self, value: Optional[str]=None, **kwargs):
        if value:
            self.media, self.port, self.proto, rest = value.split(' ', 3)
            self.port = int(self.port)
            self.fmt = rest.split(' ')
        elif 'media' in kwargs:
            self.media = kwargs.get('media')
            self.port = int(kwargs.get('port', 0))
            self.proto = kwargs.get('proto', 'RTP/AVP')
            self.fmt = kwargs.get('fmt', [])

        if 'media_attributes' in kwargs:
            self.__attribute_list = kwargs.get('media_attributes')

    def __assemble_line(self, k: str, v: str) -> str:
        """Приватный метод, выполняющий сборку пар ключ-значение в текстовые строки, с учетом наложенных ограничений

        :param k: Строка, содержащая тип ключа элемента SDP-пакета
        :param v: Строка, содержащая имя и значение элемента SDP-пакета
        :return: Строка, собранная на основе переданных параметров и имеющихся настроек
        """
        res = ''
        if k == 'a' and self.__attribute_list:
            attr_parts = v.split(':', 1)
            if attr_parts[0] in self.__attribute_list:
                res = '\r\n' + k + '=' + v
        else:
            res = '\r\n' + k + '=' + v
        return res

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление объекта класса

        :return: Строка, собранная из элементов объекта класса
        """
        result = self.media + ' ' + str(self.port) + ' ' + self.proto + ' ' + ' '.join(self.fmt)
        for k in filter(lambda x: x in self, 'icbka'):  # порядок элементов имеет значение
            if k not in SDP.multiple:  # недублируемый элемент SDP
                result += self.__assemble_line(k, str(self[k]))
            else:
                for v in self[k]:
                    result += self.__assemble_line(k, str(v))
        return result


class SDP(_Attributes):
    """Класс, предоставляющий доступ к аттрибутам полей SDP-пакета

    Имеет динамическую структуру. Доступ к элементам возможен как по ключу,
    так и по обращению к аттрибуту объекта класса. Если запрошенный элемент
    отсутствует, возвращает None.

    :param value: Строка, которую необходимо разобрать на элементы и преобразовать их в аттрибуты объекта класса
    :param allowed_attributes: Набор имен аттрибутов, допустимых для строк 'a=...'
    """

    # Ключи, которые могут дублироваться в теле SDP-пакета
    multiple = 'tramb'

    def __init__(self, value: Optional[str]=None, allowed_attributes: Optional[set]=None):
        self._allowed_attributes = allowed_attributes
        if value:
            self._parse(value)

    def _parse(self, text: str) -> None:
        """Метод, выполняющий парсинг строки на основе которой необходимо инициализировать аттрибуты объекта класса

        :param text: Строка, которую требуется распарсить
        """
        for line in text.replace('\r\n', '\n').split('\n'):
            k, sep, v = line.partition('=')

            if k == 'o':
                v = Originator(v)
            elif k == 'c':
                v = Connection(v)
            elif k == 'm':
                v = Media(v, media_attributes=self._allowed_attributes)

            if k == 'm':  # Новая строка 'm=...'
                if not self['m']:
                    self['m'] = []
                self['m'].append(v)
            else:
                if self['m']:   # Добавляем новый элемент в объект Media
                    obj = self['m'][-1]
                else:           # Добавляем новый элемент в объект SDP
                    obj = self
                obj[k] = (k in SDP.multiple and ((k in obj) and (obj[k] + [v]) or [v])) or v

    def __assemble_line(self, k: str, v: str) -> str:
        """Приватный метод, выполняющий сборку пар ключ-значение в текстовые строки, с учетом наложенных ограничений

        :param k: Строка, содержащая тип ключа элемента SDP-пакета
        :param v: Строка, содержащая имя и значение элемента SDP-пакета
        :return: Строка, собранная на основе переданных параметров и имеющихся настроек
        """
        res = ''
        if k == 'a' and self._allowed_attributes:
            attr_parts = v.split(':', 1)
            if attr_parts[0] in self._allowed_attributes:
                res = k + '=' + v + '\r\n'
        else:
            res = k + '=' + v + '\r\n'
        return res

    def __repr__(self) -> str:
        """Магический метод, возвращающий строковое представление объекта класса

        :return: Строка, собранная из элементов объекта класса
        """
        result = ''
        for k in filter(lambda x: x in self, 'vosiuepcbtam'):   # порядок элементов имеет значение
            if k not in SDP.multiple:   # недублируемый элемент SDP
                result += self.__assemble_line(k, str(self[k]))
            else:
                for v in self[k]:
                    result += self.__assemble_line(k, str(v))
        return result
