import re
import typing

# Splitter used between requests in WebScarab log files
WEBSCARAB_SPLITTER = "### Conversation"

# Encoding used for Unicode data
UNICODE_ENCODING = "utf8"

# Use "Supplementary Private Use Area-A"
INVALID_UNICODE_PRIVATE_AREA = False

SAFE_HEX_MARKER = "__SAFE_HEX__"

# String representation for NULL value
NULL = "NULL"

def filterNone(values):  # Cross-referenced function
    # replace 
    return [_ for _ in values if _] if isinstance(values, typing.collections.abc.Iterable) else values

def getUnicode(value, encoding=None, noneToNull=False):
    """
    Return the unicode representation of the supplied value:

    >>> getUnicode('test') == u'test'
    True
    >>> getUnicode(1) == u'1'
    True
    """

    if noneToNull and value is None:
        return NULL

    if isinstance(value, str):
        return value
    elif isinstance(value, bytes):
        # Heuristics (if encoding not explicitly specified)
        candidates = filterNone((encoding, kb.get("pageEncoding") if kb.get("originalPage") else None, conf.get("encoding"), UNICODE_ENCODING, sys.getfilesystemencoding()))
        if all(_ in value for _ in (b'<', b'>')):
            pass
        elif any(_ in value for _ in (b":\\", b'/', b'.')) and b'\n' not in value:
            candidates = filterNone((encoding, sys.getfilesystemencoding(), kb.get("pageEncoding") if kb.get("originalPage") else None, UNICODE_ENCODING, conf.get("encoding")))
        elif conf.get("encoding") and b'\n' not in value:
            candidates = filterNone((encoding, conf.get("encoding"), kb.get("pageEncoding") if kb.get("originalPage") else None, sys.getfilesystemencoding(), UNICODE_ENCODING))

        for candidate in candidates:
            try:
                return six.text_type(value, candidate)
            except UnicodeDecodeError:
                pass

        try:
            return six.text_type(value, encoding or (kb.get("pageEncoding") if kb.get("originalPage") else None) or UNICODE_ENCODING)
        except UnicodeDecodeError:
            return six.text_type(value, UNICODE_ENCODING, errors="reversible")
    elif isListLike(value):
        value = list(getUnicode(_, encoding, noneToNull) for _ in value)
        return value
    else:
        try:
            return six.text_type(value)
        except UnicodeDecodeError:
            return six.text_type(str(value), errors="ignore")  # encoding ignored for non-basestring instances


def getText(value, encoding=None):
    """
    Returns textual value of a given value (Note: not necessary Unicode on Python2)

    >>> getText(b"foobar")
    'foobar'
    >>> isinstance(getText(u"fo\\u2299bar"), six.text_type)
    True
    """

    retVal = value

    # replace six.binary_type with bytes
    if isinstance(value, bytes):
        retVal = getUnicode(value, encoding)

    return retVal

def decodeHex(value, binary=True):
    """
    Returns a decoded representation of provided hexadecimal value

    >>> decodeHex("313233") == b"123"
    True
    >>> decodeHex("313233", binary=False) == u"123"
    True
    """

    retVal = value

    if isinstance(value, six.binary_type):
        value = getText(value)

    if value.lower().startswith("0x"):
        value = value[2:]

    try:
        retVal = codecs.decode(value, "hex")
    except LookupError:
        retVal = binascii.unhexlify(value)

    if not binary:
        retVal = getText(retVal)

    return retVal

def getBytes(value, encoding=UNICODE_ENCODING, errors="strict", unsafe=True):
    """
    Returns byte representation of provided Unicode value

    >>> getBytes(u"foo\\\\x01\\\\x83\\\\xffbar") == b"foo\\x01\\x83\\xffbar"
    True
    """

    retVal = value

    # replace six.text_type with str
    # remove condition of INVALID_UNICODE_PRIVATE_AREA
    if isinstance(value, str):
        retVal = value.encode(encoding, errors)

        if unsafe:
            retVal = re.sub(b"\\\\x([0-9a-f]{2})", lambda _: decodeHex(_.group(1)), retVal)

    return retVal

def extractRegexResult(regex, content, flags=0):
    """
    Returns 'result' group value from a possible match with regex on a given
    content

    >>> extractRegexResult(r'a(?P<result>[^g]+)g', 'abcdefg')
    'bcdef'
    """

    retVal = None

    if regex and content and "?P<result>" in regex:
        # replace six.binary_type with bytes
        # replace six.text_type with str
        if isinstance(content, bytes) and isinstance(regex, str):
            regex = getBytes(regex)

        match = re.search(regex, content, flags)

        if match:
            retVal = match.group("result")

    return retVal


def parseRequestFile(reqFile, checkParams=True):
    """
    Parses WebScarab and Burp logs and adds results to the target URL list
    """

    def _parseWebScarabLog(content):
        """
        Parses WebScarab logs (POST method not supported)
        """

        reqResList = content.split(WEBSCARAB_SPLITTER)

        for request in reqResList:
            url = extractRegexResult(r"URL: (?P<result>.+?)\n", request, re.I)
            method = extractRegexResult(r"METHOD: (?P<result>.+?)\n", request, re.I)
            cookie = extractRegexResult(r"COOKIE: (?P<result>.+?)\n", request, re.I)

            if not method or not url:
                logger.debug("not a valid WebScarab log data")
                continue

            if method.upper() == HTTPMETHOD.POST:
                warnMsg = "POST requests from WebScarab logs aren't supported "
                warnMsg += "as their body content is stored in separate files. "
                warnMsg += "Nevertheless you can use -r to load them individually."
                logger.warning(warnMsg)
                continue

            if not(conf.scope and not re.search(conf.scope, url, re.I)):
                yield (url, method, None, cookie, tuple())

    def _parseBurpLog(content):
        """
        Parses Burp logs
        """

        if not re.search(BURP_REQUEST_REGEX, content, re.I | re.S):
            if re.search(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
                reqResList = []
                for match in re.finditer(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
                    port, request = match.groups()
                    try:
                        request = decodeBase64(request, binary=False)
                    except binascii.Error:
                        continue
                    _ = re.search(r"%s:.+" % re.escape(HTTP_HEADER.HOST), request)
                    if _:
                        host = _.group(0).strip()
                        if not re.search(r":\d+\Z", host):
                            request = request.replace(host, "%s:%d" % (host, int(port)))
                    reqResList.append(request)
            else:
                reqResList = [content]
        else:
            reqResList = re.finditer(BURP_REQUEST_REGEX, content, re.I | re.S)

        for match in reqResList:
            request = match if isinstance(match, six.string_types) else match.group(1)
            request = re.sub(r"\A[^\w]+", "", request)
            schemePort = re.search(r"(http[\w]*)\:\/\/.*?\:([\d]+).+?={10,}", request, re.I | re.S)

            if schemePort:
                scheme = schemePort.group(1)
                port = schemePort.group(2)
                request = re.sub(r"\n=+\Z", "", request.split(schemePort.group(0))[-1].lstrip())
            else:
                scheme, port = None, None

            if "HTTP/" not in request:
                continue

            if re.search(r"^[\n]*%s.*?\.(%s)\sHTTP\/" % (HTTPMETHOD.GET, "|".join(CRAWL_EXCLUDE_EXTENSIONS)), request, re.I | re.M):
                continue

            getPostReq = False
            url = None
            host = None
            method = None
            data = None
            cookie = None
            params = False
            newline = None
            lines = request.split('\n')
            headers = []

            for index in xrange(len(lines)):
                line = lines[index]

                if not line.strip() and index == len(lines) - 1:
                    break

                newline = "\r\n" if line.endswith('\r') else '\n'
                line = line.strip('\r')
                match = re.search(r"\A([A-Z]+) (.+) HTTP/[\d.]+\Z", line) if not method else None

                if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
                    data = ""
                    params = True

                elif match:
                    method = match.group(1)
                    url = match.group(2)

                    if any(_ in line for _ in ('?', '=', kb.customInjectionMark)):
                        params = True

                    getPostReq = True

                # POST parameters
                elif data is not None and params:
                    data += "%s%s" % (line, newline)

                # GET parameters
                elif "?" in line and "=" in line and ": " not in line:
                    params = True

                # Headers
                elif re.search(r"\A\S+:", line):
                    key, value = line.split(":", 1)
                    value = value.strip().replace("\r", "").replace("\n", "")

                    # Cookie and Host headers
                    if key.upper() == HTTP_HEADER.COOKIE.upper():
                        cookie = value
                    elif key.upper() == HTTP_HEADER.HOST.upper():
                        if '://' in value:
                            scheme, value = value.split('://')[:2]
                        splitValue = value.split(":")
                        host = splitValue[0]

                        if len(splitValue) > 1:
                            port = filterStringValue(splitValue[1], "[0-9]")

                    # Avoid to add a static content length header to
                    # headers and consider the following lines as
                    # POSTed data
                    if key.upper() == HTTP_HEADER.CONTENT_LENGTH.upper():
                        params = True

                    # Avoid proxy and connection type related headers
                    elif key not in (HTTP_HEADER.PROXY_CONNECTION, HTTP_HEADER.CONNECTION):
                        headers.append((getUnicode(key), getUnicode(value)))

                    if kb.customInjectionMark in re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value or ""):
                        params = True

            data = data.rstrip("\r\n") if data else data

            if getPostReq and (params or cookie or not checkParams):
                if not port and hasattr(scheme, "lower") and scheme.lower() == "https":
                    port = "443"
                elif not scheme and port == "443":
                    scheme = "https"

                if conf.forceSSL:
                    scheme = "https"
                    port = port or "443"

                if not host:
                    errMsg = "invalid format of a request file"
                    raise SqlmapSyntaxException(errMsg)

                if not url.startswith("http"):
                    url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)
                    scheme = None
                    port = None

                if not(conf.scope and not re.search(conf.scope, url, re.I)):
                    yield (url, conf.method or method, data, cookie, tuple(headers))

    content = readCachedFileContent(reqFile)

    if conf.scope:
        logger.info("using regular expression '%s' for filtering targets" % conf.scope)

    for target in _parseBurpLog(content):
        yield target

    for target in _parseWebScarabLog(content):
        yield target