// Copyright 2007-2021 The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_WEBSOCKET_H_
#define MUMBLE_WEBSOCKET_H_

#include <QtCore/QtGlobal>
#include <QtNetwork/QSslSocket>

enum WebSocketState { None, Handshake, Open, Closed, Error };

enum WebSocketNextAction { ReadOpcodeAnd1ByteLength, Read2ByteLength, Read8ByteLength, ReadMask, ReadPayload };
enum WebSocketNextPayload { Data, Ping, Pong };

// Only supports server mode
class WebSocket {
private:
	static const QByteArray magicSequence;
	static const QByteArray serverHeader;
	static const char msgHeader;
	static const char pongHeader;
	WebSocketState wsState;
	QByteArray webSocketAccept;
	unsigned char mask[4];
	quint8 maskIndex;
	QList< QByteArray > buffers;
	quint64 bytesInBuffers;
	WebSocketNextAction nextAction;
	quint64 nextLength;
	quint64 buffersFirstConsumed;
	WebSocketNextPayload nextPayload;
	void unmask(char *data, quint64 len);
	void socketReadHandshake(QSslSocket *qtsSocket);
	void socketReadOpen(QSslSocket *qtsSocket);
	void writeLength(QSslSocket *qtsSocket, quint64 length);

public:
	// Writes a single frame binary message according to the WebSocket protocol.
	// If state() is not Open, this is a no-op.
	void write(QSslSocket *qtsSocket, const QByteArray &qbaMsg);
	// Reads bytes from the underlying socket and updates bytesAvailable() if
	// application data get available. WebSocket text messages are considered
	// binary messages, too. If a ping frame is received, a pong frame is send back
	// automatically. If a close frame is received, a close frame is send back and
	// the state will be updated accordingly. This implementation does not care about
	// preserving WebSocket procotol messages; all received non-control frames will be
	// made available as binary data, obtainable by read(), discarding any concept of
	// WebSocket message framing, including fragmentation.
	void socketRead(QSslSocket *qtsSocket);
	qint64 read(char *buf, qint64 maxLen);
	QByteArray read(qint64 maxLen);
	qint64 bytesAvailable();
	WebSocketState state();
};

#endif
