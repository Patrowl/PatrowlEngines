# !/usr/bin/python
import socket
import ssl


SOCKET_DEFAULT_TIMEOUT = 2


def grab_tcp_banner(target: str, port: int):
    """Grab banner from remote TCP service."""
    try:
        # Create a socket
        s = socket.socket()
        s.settimeout(SOCKET_DEFAULT_TIMEOUT)

        # Connect to the HTTPS server
        s.connect((target, port))

        # Receive data from server
        banner = s.recv(4094)
        s.close()

        return banner.decode('utf-8'), False
    except Exception:
        pass
    s.close()
    return '', True


def grab_http_banner(target: str, port: int):
    """Grab banner from remote HTTP service."""
    try:
        # Create a socket
        s = socket.socket()
        s.settimeout(SOCKET_DEFAULT_TIMEOUT)

        # Connect to the HTTP server
        s.connect((target, port))

        # Form a HTTP request
        msg = 'GET / HTTP/1.1\nHost: ' + target + '\n\n'
        # msg = 'GET / HTTP/1.0\n\n'
        # print(msg)
        s.send(str.encode(msg))

        # Receive data from server
        banner = s.recv(4094)

        s.close()

        return banner.decode('utf-8'), False
    except Exception:
        pass

    s.close()
    return '', True


def grab_https_banner(target: str, port: int):
    """Grab banner from remote SSL service."""
    try:
        # SSL Context creation
        contextInstance = ssl.SSLContext()
        contextInstance.verify_mode = ssl.CERT_NONE

        # Create a socket
        s = socket.socket()
        s.settimeout(SOCKET_DEFAULT_TIMEOUT)

        # Make the socket TLS compliant
        ss = contextInstance.wrap_socket(s, do_handshake_on_connect=False)

        # Connect to the HTTPS server
        ss.connect((target, port))

        # Complete the TLS handshake
        ss.do_handshake()

        # Form a HTTP request
        msg = 'GET / HTTP/1.0\nHost: ' + target + '\n\n'
        ss.send(str.encode(msg))

        # Receive data from server
        banner = ss.recv(4094)

        # Close the sockets
        ss.close()
        s.close()

        return banner.decode('utf-8'), False
    except Exception:
        pass

    s.close()
    return '', True


def grab_banner(host: str, port: int) -> str:
    """Grab banner from remote service."""
    # print("Check TCP/", port)
    resp, err = grab_tcp_banner(host, port)
    if err is False and resp not in [None, '']:
        return resp

    if err is True and resp == '':
        # print("Check HTTP/", port)
        resp, err = grab_http_banner(host, port)

    https_required = [
        'HTTPS is required',
        'The plain HTTP request was sent to HTTPS'
    ]
    if any(x in resp for x in https_required):
        # print("Check HTTPS/", port)
        resp, err = grab_https_banner(host, port)

    return resp


def main():
    ports = [22, 80, 443]
    host = 'patrowl.io'
    for port in ports:
        resp = grab_banner(host, port)
        print(resp)


if __name__ == '__main__':
    main()
