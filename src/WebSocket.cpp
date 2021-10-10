#include "WebSocket.h"

#include <QCryptographicHash>
#include <QtCore/QtEndian>

const QByteArray WebSocket::magicSequence = QString("258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toUtf8();
const QByteArray WebSocket::serverHeader =
	QString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
		.toUtf8();

// Corresponds to single frame binary message (fin bit set, last four bits equal 2).
const char WebSocket::msgHeader  = 0b10000010;
const char WebSocket::pongHeader = 0x0A | 0b10000000;

WebSocketState WebSocket::state() {
	return wsState;
}

void WebSocket::socketReadHandshake(QSslSocket *qtsSocket) {
	// For the handshake header we are only interested in the
	// Sec-WebSocket-Key and ignore the rest. We are not checking
	// the header for http standard conformity.

	// Since this is a http header, we can read it line by line.
	while (qtsSocket->canReadLine()) {
		// IMPORTANT? Note: According to the docs at
		// https://doc.qt.io/qt-5/qiodevice.html#readLine-1 on Windows,
		// "newline characters are replaced with \n". If this is true,
		// we need to replace it back, since http headers should have "\r\n"!
		// Someone needs to test this though.
		const QByteArray lineAscii = qtsSocket->readLine();
		QString line               = QString::fromUtf8(lineAscii);
#ifdef Q_OS_WIN
		// TODO: Build on Windows and check if the lines end with \n or \r\n
		qWarning() << line;
		// If ending with only \n, maybe use this:
		// line.resize(line.length() + 1, '\n');
		// line[line.length() - 2] = '\r';
#endif
		if (line.startsWith("Sec-WebSocket-Key:", Qt::CaseInsensitive)) {
			// The key is a 16 byte base64 encoded sequence, so it should always
			// be 24 bytes long.
			// Get the lenth without "Sec-WebSocket-Key:".
			int restLength = line.length() - 18;
			// The restLength must contain the 24 characters of the key plus \r\n
			// at the end, or else we got a protocol violation here. Since there
			// could be additional whitespaces according to the http standard,
			// there might be more characters.
			if (restLength < 24 + 2) {
				qWarning() << "WebSocket Error: Client's Sec-WebSocket-Key is invalid!";
				wsState = WebSocketState::Error;
				return;
			}
			QByteArray keyOnly = QStringRef(&line, 18, restLength).trimmed().toUtf8();
			webSocketAccept =
				QCryptographicHash::hash(keyOnly.append(magicSequence), QCryptographicHash::Algorithm::Sha1).toBase64();

		} else if (lineAscii.length() == 2 && lineAscii[0] == '\r' && lineAscii[1] == '\n') {
			// This is the end of the header, check if we have a webSocketAccept.
			if (webSocketAccept.isNull()) {
				qWarning() << "WebSocket Error: Client's Sec-WebSocket-Key is missing!";
				wsState = WebSocketState::Error;
				return;
			}
			// Write out our handshake.
			qtsSocket->write(serverHeader);
			qtsSocket->write(webSocketAccept);
			qtsSocket->write(lineAscii); // At this point this is just \r\n
			qtsSocket->write(lineAscii);
			qtsSocket->flush();
			wsState = WebSocketState::Open;
			break;
		}
	}
}

void WebSocket::socketReadOpen(QSslSocket *qtsSocket) {
	while (true) {
		qint64 iAvailable = qtsSocket->bytesAvailable();
		switch (nextAction) {
			case WebSocketNextAction::ReadOpcodeAnd1ByteLength: {
				if (iAvailable < 2)
					return;

				unsigned char headerBuffer[2];
				qtsSocket->read(reinterpret_cast< char * >(headerBuffer), 2);
				iAvailable -= 2;

				// For the first byte we do not care about the fin and reserverd
				// bits, so do some masking and take only the last 4 bits.
				headerBuffer[0] &= 0b00001111;
				// Next, we will treat continuation (0) and text (1) frames the same as
				// binary (2) frames.
				if (headerBuffer[0] <= 0x02) {
					nextPayload = WebSocketNextPayload::Data;
				} else if (headerBuffer[0] == 0x08) {
					// Close frame
					// A close frame may contain masked data like a normal frame
					// describing the cause of the close, but we will ignore this data.
					// If we received a close frame, send one back and enter the closed state.
					// We use the headerBuffer for this.
					headerBuffer[0] |= 0b10000000; // Set the fin bit, opcode is already 0x08
					headerBuffer[1] = 0;           // We won't transmit data in the close frame, so set the length to 0
					qtsSocket->write(reinterpret_cast< char * >(headerBuffer), 2);
					wsState = WebSocketState::Closed;
					return;
				} else if (headerBuffer[0] == 0x09) {
					// Ping frame
					nextPayload = WebSocketNextPayload::Ping;
				} else if (headerBuffer[0] == 0x0A) {
					// Pong frame
					nextPayload = WebSocketNextPayload::Pong;
				} else {
					// Unknown
					qWarning() << "WebSocket Error: Unknown frame type" << headerBuffer[0];
					wsState = WebSocketState::Error;
					return;
				}

				// Since this is a message send from a client to a server, the mask bit must be there.
				bool maskBit = (headerBuffer[1] & 0b10000000) != 0;
				if (!maskBit) {
					qWarning() << "WebSocket Error: Masking bit in client frame not set!";
					wsState = WebSocketState::Error;
					return;
				}

				// Mask away the mask bit to figure out the length
				headerBuffer[1] &= 0b01111111;
				if (headerBuffer[1] <= 125) {
					// This is the length, continue by reading the mask.
					nextLength = headerBuffer[1];
					nextAction = WebSocketNextAction::ReadMask;
				} else if (headerBuffer[1] == 126) {
					nextAction = WebSocketNextAction::Read2ByteLength;
				} else if (headerBuffer[1] == 127) {
					nextAction = WebSocketNextAction::Read8ByteLength;
				} else {
					// Should never reach this.
					qWarning() << "WebSocket Error: Received bad length code" << headerBuffer[1];
					wsState = WebSocketState::Error;
					return;
				}
			} break;

			case WebSocketNextAction::Read2ByteLength: {
				if (iAvailable < 2)
					return;

				unsigned char lengthBuffer2[2];
				qtsSocket->read(reinterpret_cast< char * >(lengthBuffer2), 2);
				iAvailable -= 2;
				nextLength = qFromBigEndian< quint16 >(&lengthBuffer2[0]);
				nextAction = WebSocketNextAction::ReadMask;
			} break;

			case WebSocketNextAction::Read8ByteLength: {
				if (iAvailable < 8)
					return;

				unsigned char lengthBuffer8[8];
				qtsSocket->read(reinterpret_cast< char * >(lengthBuffer8), 8);
				iAvailable -= 8;
				nextLength = qFromBigEndian< quint64 >(&lengthBuffer8[0]);
				nextAction = WebSocketNextAction::ReadMask;
			} break;

			case WebSocketNextAction::ReadMask: {
				if (iAvailable < 4)
					return;

				qtsSocket->read(reinterpret_cast< char * >(mask), 4);
				iAvailable -= 4;
				maskIndex  = 0;
				nextAction = WebSocketNextAction::ReadPayload;
			} break;

			case WebSocketNextAction::ReadPayload: {
				switch (nextPayload) {
					case WebSocketNextPayload::Pong: {
						// If the next data belong to a pong, just ignore them
						if (nextLength <= (quint64) iAvailable) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
							qtsSocket->skip(nextLength);
#else
							qtsSocket->read(nextLength);
#endif
							iAvailable -= nextLength;
							nextAction = WebSocketNextAction::ReadOpcodeAnd1ByteLength;
						} else {
							return;
						}
					} break;
					case WebSocketNextPayload::Ping: {
						// If the next data belong to a ping, we need to received them
						// and send them back. The data will arrive masked, so we need
						// to unmask them first.
						if (nextLength <= (quint64) iAvailable) {
							QByteArray pingData = qtsSocket->read(nextLength);
							unmask(pingData.data(), nextLength);
							iAvailable -= nextLength;
							qtsSocket->write(&pongHeader, 1);
							writeLength(qtsSocket, pingData.length());
							qtsSocket->write(pingData);
							nextAction = WebSocketNextAction::ReadOpcodeAnd1ByteLength;
						} else {
							return;
						}
					} break;

					case WebSocketNextPayload::Data: {
						if (nextLength == 0) {
							nextAction = WebSocketNextAction::ReadOpcodeAnd1ByteLength;
							continue;
						}
						if (iAvailable == 0)
							return;

						quint64 read    = nextLength < (quint64) iAvailable ? nextLength : iAvailable;
						QByteArray data = qtsSocket->read(read);
						iAvailable -= read;
						nextLength -= read;
						unmask(data.data(), read);
						buffers << data;
						bytesInBuffers += read;
					} break;
				}
			} break;
		}
	}
}

void WebSocket::unmask(char *data, quint64 len) {
	for (quint64 i = 0; i < len; i++) {
		data[i] ^= mask[maskIndex];
		maskIndex++;
		if (maskIndex == 4) {
			maskIndex = 0;
		}
	}
}

void WebSocket::socketRead(QSslSocket *qtsSocket) {
	if (wsState == WebSocketState::None) {
		wsState = WebSocketState::Handshake;
	}
	if (wsState == WebSocketState::Handshake) {
		socketReadHandshake(qtsSocket);
	}
	if (wsState == WebSocketState::Open) {
		socketReadOpen(qtsSocket);
	}
}


void WebSocket::writeLength(QSslSocket *qtsSocket, quint64 length) {
	char len;
	if (length <= 125) {
		len = (char) length;
		qtsSocket->write(&len, 1);
	} else if (length <= 65536) {
		len = 126;
		qtsSocket->write(&len, 1);
		quint16 length16 = length;
		char lenBuffer[2];
		qToBigEndian(length16, lenBuffer);
		qtsSocket->write(lenBuffer, 2);
	} else {
		len = 127;
		qtsSocket->write(&len, 1);
		char lenBuffer[8];
		qToBigEndian(length, lenBuffer);
		qtsSocket->write(lenBuffer, 8);
	}
}

void WebSocket::write(QSslSocket *qtsSocket, const QByteArray &qbaMsg) {
	if (wsState == WebSocketState::Open) {
		qtsSocket->write(&msgHeader, 1);
		writeLength(qtsSocket, qbaMsg.length());
		qtsSocket->write(qbaMsg);
	}
}

qint64 WebSocket::read(char *buf, qint64 maxLen) {
	qint64 len = 0;
	while (!buffers.isEmpty()) {
		quint64 remainingInFirst = buffers[0].length() - buffersFirstConsumed;
		if (remainingInFirst == 0) {
			buffers.removeFirst();
			buffersFirstConsumed = 0;
			continue;
		}
		if (maxLen == 0) {
			break;
		}
		quint64 readStep     = remainingInFirst < (quint64) maxLen ? remainingInFirst : maxLen;
		const char *readFrom = buffers[0].constData() + buffersFirstConsumed;
		memcpy(buf + len, readFrom, readStep);
		maxLen -= readStep;
		buffersFirstConsumed += readStep;
		len += readStep;
		bytesInBuffers -= readStep;
	}
	return len;
}

QByteArray WebSocket::read(qint64 maxLen) {
	quint64 target   = (quint64) maxLen < bytesInBuffers ? maxLen : bytesInBuffers;
	QByteArray array = QByteArray(target, 0);
	read(array.data(), target);
	return array;
}

qint64 WebSocket::bytesAvailable() {
	return bytesInBuffers;
}