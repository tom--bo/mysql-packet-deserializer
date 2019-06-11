package mysqlpacket

import (
	"fmt"
)

var (
	DEBUG = false
)

func DeserializePacket(packet []byte) []IMySQLPacket {
	plen := len(packet)
	nowPos := 0
	mysqlPackets := []IMySQLPacket{}

	for plen-nowPos > 2 {
		pktLen := int(uint32(packet[nowPos]) | uint32(packet[nowPos+1])<<8 | uint32(packet[nowPos+2])<<16)
		if pktLen > 65536 || plen < nowPos+(4+pktLen) { // Todo
			return []IMySQLPacket{UnknownPacket{MySQLHeader{0, 0}, &Command{UNKNOWN_PACKET}}}
		}

		p := mapPacket(pktLen, packet[nowPos:nowPos+(4+pktLen)])
		if p == nil {
			p = UnknownPacket{MySQLHeader{0, 0}, &Command{UNKNOWN_PACKET}}
		}

		mysqlPackets = append(mysqlPackets, p)
		nowPos += 4 + pktLen
		// stop processing multiple MySQL packet
		break
	}

	return mysqlPackets
}

func judgeLowerCapacityFlags(packets []byte) []CapacityFlag {
	ret := []CapacityFlag{}
	upperFlag := map[int]CapacityFlag{
		0x0001: CLIENT_LONG_PASSWORD,
		0x0002: CLIENT_FOUND_ROWS,
		0x0004: CLIENT_LONG_FLAG,
		0x0008: CLIENT_CONNECT_WITH_DB,
		0x0010: CLIENT_NO_SCHEMA,
		0x0020: CLIENT_COMPRESS,
		0x0040: CLIENT_ODBC,
		0x0080: CLIENT_LOCAL_FILES,
		0x0100: CLIENT_IGNORE_SPACE,
		0x0200: CLIENT_41,
		0x0400: CLIENT_INTERACTIVE,
		0x0800: CLIENT_SSL,
		0x1000: CLIENT_IGNORE_SIGPIPE,
		0x2000: CLIENT_TRANSACTIONS,
		0x4000: CLIENT_RESERVED,
		0x8000: CLIENT_SECURE_CONNECTION,
	}
	upper := int(uint32(packets[1])<<8 | uint32(packets[0]))

	for k, v := range upperFlag {
		if upper&k == k {
			ret = append(ret, v)
		}
	}
	return ret
}

func judgeUpperCapacityFlags(packets []byte) []CapacityFlag {
	ret := []CapacityFlag{}

	lowerFlag := map[int]CapacityFlag{
		0x0001: CLIENT_MULTI_STATEMENTS,
		0x0002: CLIENT_MULTI_RESULTS,
		0x0004: CLIENT_PS_MULTI_RESULTS,
		0x0008: CLIENT_PLUGIN_AUTH,
		0x0010: CLIENT_CONNECT_ATTRS,
		0x0020: CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
		0x0040: CLIENT_CAN_HANDLE_EXPIRED_PASSWORD,
		0x0080: CLIENT_SESSION_TRACK,
		0x0100: CLIENT_DEPRECATE_EOF,
	}

	lower := int(uint32(packets[1])<<8 | uint32(packets[0]))

	for k, v := range lowerFlag {
		if lower&k == k {
			ret = append(ret, v)
		}
	}

	return ret
}

func judgeCapacityFlags(packets []byte) []CapacityFlag {
	ret := []CapacityFlag{}

	ret = append(ret, judgeLowerCapacityFlags(packets[0:2])...)
	ret = append(ret, judgeUpperCapacityFlags(packets[2:4])...)

	return ret
}

func judgeCharacterSet(cset byte) CharacterSet {
	charSet := map[int]CharacterSet{
		3:   DEC8_COLLATE_DEC8_SWEDISH_CI,
		4:   CP850_COLLATE_CP850_GENERAL_CI,
		5:   LATIN1_COLLATE_LATIN1_GERMAN1_CI,
		6:   HP8_COLLATE_HP8_ENGLISH_CI,
		7:   KOI8R_COLLATE_KOI8R_GENERAL_CI,
		8:   LATIN1_COLLATE_LATIN1_SWEDISH_CI,
		9:   LATIN2_COLLATE_LATIN2_GENERAL_CI,
		10:  SWE7_COLLATE_SWE7_SWEDISH_CI,
		11:  ASCII_COLLATE_ASCII_GENERAL_CI,
		14:  CP1251_COLLATE_CP1251_BULGARIAN_CI,
		15:  LATIN1_COLLATE_LATIN1_DANISH_CI,
		16:  HEBREW_COLLATE_HEBREW_GENERAL_CI,
		20:  LATIN7_COLLATE_LATIN7_ESTONIAN_CS,
		21:  LATIN2_COLLATE_LATIN2_HUNGARIAN_CI,
		22:  KOI8U_COLLATE_KOI8U_GENERAL_CI,
		23:  CP1251_COLLATE_CP1251_UKRAINIAN_CI,
		25:  GREEK_COLLATE_GREEK_GENERAL_CI,
		26:  CP1250_COLLATE_CP1250_GENERAL_CI,
		27:  LATIN2_COLLATE_LATIN2_CROATIAN_CI,
		29:  CP1257_COLLATE_CP1257_LITHUANIAN_CI,
		30:  LATIN5_COLLATE_LATIN5_TURKISH_CI,
		31:  LATIN1_COLLATE_LATIN1_GERMAN2_CI,
		32:  ARMSCII8_COLLATE_ARMSCII8_GENERAL_CI,
		33:  UTF8_COLLATE_UTF8_GENERAL_CI,
		36:  CP866_COLLATE_CP866_GENERAL_CI,
		37:  KEYBCS2_COLLATE_KEYBCS2_GENERAL_CI,
		38:  MACCE_COLLATE_MACCE_GENERAL_CI,
		39:  MACROMAN_COLLATE_MACROMAN_GENERAL_CI,
		40:  CP852_COLLATE_CP852_GENERAL_CI,
		41:  LATIN7_COLLATE_LATIN7_GENERAL_CI,
		42:  LATIN7_COLLATE_LATIN7_GENERAL_CS,
		43:  MACCE_COLLATE_MACCE_BIN,
		44:  CP1250_COLLATE_CP1250_CROATIAN_CI,
		45:  UTF8MB4_COLLATE_UTF8MB4_GENERAL_CI,
		46:  UTF8MB4_COLLATE_UTF8MB4_BIN,
		47:  LATIN1_COLLATE_LATIN1_BIN,
		48:  LATIN1_COLLATE_LATIN1_GENERAL_CI,
		49:  LATIN1_COLLATE_LATIN1_GENERAL_CS,
		50:  CP1251_COLLATE_CP1251_BIN,
		51:  CP1251_COLLATE_CP1251_GENERAL_CI,
		52:  CP1251_COLLATE_CP1251_GENERAL_CS,
		53:  MACROMAN_COLLATE_MACROMAN_BIN,
		57:  CP1256_COLLATE_CP1256_GENERAL_CI,
		58:  CP1257_COLLATE_CP1257_BIN,
		59:  CP1257_COLLATE_CP1257_GENERAL_CI,
		63:  BINARY_COLLATE_BINARY,
		64:  ARMSCII8_COLLATE_ARMSCII8_BIN,
		65:  ASCII_COLLATE_ASCII_BIN,
		66:  CP1250_COLLATE_CP1250_BIN,
		67:  CP1256_COLLATE_CP1256_BIN,
		68:  CP866_COLLATE_CP866_BIN,
		69:  DEC8_COLLATE_DEC8_BIN,
		70:  GREEK_COLLATE_GREEK_BIN,
		71:  HEBREW_COLLATE_HEBREW_BIN,
		72:  HP8_COLLATE_HP8_BIN,
		73:  KEYBCS2_COLLATE_KEYBCS2_BIN,
		74:  KOI8R_COLLATE_KOI8R_BIN,
		75:  KOI8U_COLLATE_KOI8U_BIN,
		77:  LATIN2_COLLATE_LATIN2_BIN,
		78:  LATIN5_COLLATE_LATIN5_BIN,
		79:  LATIN7_COLLATE_LATIN7_BIN,
		80:  CP850_COLLATE_CP850_BIN,
		81:  CP852_COLLATE_CP852_BIN,
		82:  SWE7_COLLATE_SWE7_BIN,
		83:  UTF8_COLLATE_UTF8_BIN,
		92:  GEOSTD8_COLLATE_GEOSTD8_GENERAL_CI,
		93:  GEOSTD8_COLLATE_GEOSTD8_BIN,
		94:  LATIN1_COLLATE_LATIN1_SPANISH_CI,
		99:  CP1250_COLLATE_CP1250_POLISH_CI,
		192: UTF8_COLLATE_UTF8_UNICODE_CI,
		193: UTF8_COLLATE_UTF8_ICELANDIC_CI,
		194: UTF8_COLLATE_UTF8_LATVIAN_CI,
		195: UTF8_COLLATE_UTF8_ROMANIAN_CI,
		196: UTF8_COLLATE_UTF8_SLOVENIAN_CI,
		197: UTF8_COLLATE_UTF8_POLISH_CI,
		198: UTF8_COLLATE_UTF8_ESTONIAN_CI,
		199: UTF8_COLLATE_UTF8_SPANISH_CI,
		200: UTF8_COLLATE_UTF8_SWEDISH_CI,
		201: UTF8_COLLATE_UTF8_TURKISH_CI,
		202: UTF8_COLLATE_UTF8_CZECH_CI,
		203: UTF8_COLLATE_UTF8_DANISH_CI,
		204: UTF8_COLLATE_UTF8_LITHUANIAN_CI,
		205: UTF8_COLLATE_UTF8_SLOVAK_CI,
		206: UTF8_COLLATE_UTF8_SPANISH2_CI,
		207: UTF8_COLLATE_UTF8_ROMAN_CI,
		208: UTF8_COLLATE_UTF8_PERSIAN_CI,
		209: UTF8_COLLATE_UTF8_ESPERANTO_CI,
		210: UTF8_COLLATE_UTF8_HUNGARIAN_CI,
		211: UTF8_COLLATE_UTF8_SINHALA_CI,
		212: UTF8_COLLATE_UTF8_GERMAN2_CI,
		213: UTF8_COLLATE_UTF8_CROATIAN_CI,
		214: UTF8_COLLATE_UTF8_UNICODE_520_CI,
		215: UTF8_COLLATE_UTF8_VIETNAMESE_CI,
		223: UTF8_COLLATE_UTF8_GENERAL_MYSQL500_CI,
		224: UTF8MB4_COLLATE_UTF8MB4_UNICODE_CI,
		225: UTF8MB4_COLLATE_UTF8MB4_ICELANDIC_CI,
		226: UTF8MB4_COLLATE_UTF8MB4_LATVIAN_CI,
		227: UTF8MB4_COLLATE_UTF8MB4_ROMANIAN_CI,
		228: UTF8MB4_COLLATE_UTF8MB4_SLOVENIAN_CI,
		229: UTF8MB4_COLLATE_UTF8MB4_POLISH_CI,
		230: UTF8MB4_COLLATE_UTF8MB4_ESTONIAN_CI,
		231: UTF8MB4_COLLATE_UTF8MB4_SPANISH_CI,
		232: UTF8MB4_COLLATE_UTF8MB4_SWEDISH_CI,
		233: UTF8MB4_COLLATE_UTF8MB4_TURKISH_CI,
		234: UTF8MB4_COLLATE_UTF8MB4_CZECH_CI,
		235: UTF8MB4_COLLATE_UTF8MB4_DANISH_CI,
		236: UTF8MB4_COLLATE_UTF8MB4_LITHUANIAN_CI,
		237: UTF8MB4_COLLATE_UTF8MB4_SLOVAK_CI,
		238: UTF8MB4_COLLATE_UTF8MB4_SPANISH2_CI,
		239: UTF8MB4_COLLATE_UTF8MB4_ROMAN_CI,
		240: UTF8MB4_COLLATE_UTF8MB4_PERSIAN_CI,
		241: UTF8MB4_COLLATE_UTF8MB4_ESPERANTO_CI,
		242: UTF8MB4_COLLATE_UTF8MB4_HUNGARIAN_CI,
		243: UTF8MB4_COLLATE_UTF8MB4_SINHALA_CI,
		244: UTF8MB4_COLLATE_UTF8MB4_GERMAN2_CI,
		245: UTF8MB4_COLLATE_UTF8MB4_CROATIAN_CI,
		246: UTF8MB4_COLLATE_UTF8MB4_UNICODE_520_CI,
		247: UTF8MB4_COLLATE_UTF8MB4_VIETNAMESE_CI,
	}
	cset_int := int(uint32(cset))

	for k, v := range charSet {
		if cset_int&k == k {
			return v
		}
	}

	return UNKNOWN_CHARACTER_SET
}

func judgeStatusFlags(packet []byte) []GeneralPacketStatusFlag {
	ret := []GeneralPacketStatusFlag{}

	generalStatus := map[int]GeneralPacketStatusFlag{
		0x0001: SERVER_STATUS_IN_TRANS,
		0x0002: SERVER_STATUS_AUTOCOMMIT,
		0x0008: SERVER_MORE_RESULTS_EXISTS,
		0x0010: SERVER_STATUS_NO_GOOD_INDEX_USED,
		0x0020: SERVER_STATUS_NO_INDEX_USED,
		0x0040: SERVER_STATUS_CURSOR_EXISTS,
		0x0080: SERVER_STATUS_LAST_ROW_SENT,
		0x0100: SERVER_STATUS_DB_DROPPED,
		0x0200: SERVER_STATUS_NO_BACKSLASH_ESCAPES,
		0x0400: SERVER_STATUS_METADATA_CHANGE,
		0x0800: SERVER_QUERY_WAS_SLOW,
		0x1000: SERVER_PS_OUT_PARAMS,
		0x2000: SERVER_STATUS_IN_TRANS_READONLY,
		0x4000: SERVER_SESSION_STATE_CHANGED,
	}

	byte2 := int(packet[1]<<8 | packet[0])

	for k, v := range generalStatus {
		if byte2&k == k {
			ret = append(ret, v)
		}
	}

	return ret
}

func judgeColumnType(p byte) ColumnType {
	columnType := map[int]ColumnType{
		0x00: TYPE_DECIMAL,
		0x01: TYPE_TINY,
		0x02: TYPE_SHORT,
		0x03: TYPE_LONG,
		0x04: TYPE_FLOAT,
		0x05: TYPE_DOUBLE,
		0x06: TYPE_NULL,
		0x07: TYPE_TIMESTAMP,
		0x08: TYPE_LONGLONG,
		0x09: TYPE_INT24,
		0x0a: TYPE_DATE,
		0x0b: TYPE_TIME,
		0x0c: TYPE_DATETIME,
		0x0d: TYPE_YEAR,
		0x0e: TYPE_NEWDATE,
		0x0f: TYPE_VARCHAR,
		0x10: TYPE_BIT,
		0x11: TYPE_TIMESTAMP2,
		0x12: TYPE_DATETIME2,
		0x13: TYPE_TIME2,
		0xf6: TYPE_NEWDECIMAL,
		0xf7: TYPE_ENUM,
		0xf8: TYPE_SET,
		0xf9: TYPE_TINY_BLOB,
		0xfa: TYPE_MEDIUM_BLOB,
		0xfb: TYPE_LONG_BLOB,
		0xfc: TYPE_BLOB,
		0xfd: TYPE_VAR_STRING,
		0xfe: TYPE_STRING,
		0xff: TYPE_GEOMETRY,
	}
	pint := int(p)

	for k, v := range columnType {
		if pint&k == k {
			return v
		}
	}

	return TYPE_UNKNOWN
}

func decodeLengthEncodedInt(packet []byte) (int, int) {
	if packet[0] == 0x00 {
		return 0, 0
	}
	if packet[0] < 0xfc {
		return 1, int(uint8(packet[0]))
	}
	switch packet[0] {
	case 0xfc:
		return 2, int(uint32(packet[2])<<8 | uint32(packet[1]))
	case 0xfd:
		return 3, int(uint32(packet[3])<<16 | uint32(packet[2])<<8 | uint32(packet[1]))
	case 0xfe:
		return 8, int(
			uint64(packet[8])<<56 | uint64(packet[7])<<48 | uint64(packet[6]<<40) |
				uint64(packet[5])<<32 | uint64(packet[4])<<24 | uint64(packet[3])<<16 |
				uint64(packet[2])<<8 | uint64(packet[1]))
	}
	return 0, 0
}

// This func returns (total-length, str-content)
// string<lenenc> := int<lenenc> + string<lenenc>
func decodeLengthEncodedString(packet []byte) (int, string) {
	ilen := 0
	slen := 0
	if packet[0] == 0x00 {
		return 0, ""
	}
	if packet[0] < 0xfc {
		ilen = 1
		slen = int(uint8(packet[0]))
	}
	switch packet[0] {
	case 0xfc:
		ilen = 2
		slen = int(uint32(packet[2])<<8 | uint32(packet[1]))
	case 0xfd:
		ilen = 3
		slen = int(uint32(packet[3])<<16 | uint32(packet[2])<<8 | uint32(packet[1]))
	case 0xfe:
		ilen = 8

		slen = int(
			uint64(packet[8])<<56 | uint64(packet[7])<<48 | uint64(packet[6]<<40) |
				uint64(packet[5])<<32 | uint64(packet[4])<<24 | uint64(packet[3])<<16 |
				uint64(packet[2])<<8 | uint64(packet[1]))
	}
	return ilen + slen, string(packet[ilen : ilen+slen])
}

func mapPacket(plen int, packet []byte) IMySQLPacket {
	defer func() {
		if err := recover(); err != nil && DEBUG {
			fmt.Println("[DEBUG] Error!!!")
			fmt.Println(err)
		}
	}()

	sid := int(packet[3])
	ctype := packet[4]
	mHeader := MySQLHeader{uint32(plen), uint8(sid)}

	/*
	 * general response or connection phase packet
	 */

	// At first, judge no header packet (Header + 13~35 byte are all 00)
	// HandshakeResponse41 or SSLRequest
	if plen > 35 {
		allZero := true
		for _, p := range packet[13:36] {
			if p != 0x00 {
				allZero = false
			}
		}
		if allZero {
			flags := judgeCapacityFlags(packet[4:8])
			maxPacketSize := int(uint32(packet[8]) | uint32(packet[9])<<8 | uint32(packet[10])<<16 | uint32(packet[11])<<24)
			cset := judgeCharacterSet(packet[12])
			if plen <= 36 { // SSL_REQUESj
				return SSLRequest{mHeader, &Command{SSL_REQUEST}, flags, maxPacketSize, cset}
			} else { // HANDSHAKE_RESPONSE41
				// HANDSHAKE_RESPONSE41 is not completely implemented
				return HandshakeResponse41{mHeader, &Command{HANDSHAKE_RESPONSE41}, flags, maxPacketSize, cset}
			}
		}
	}

	// Second, judge auth plugin response (all string)
	if ctype > 0x1f && ctype < 0xfe {
		return AuthSwitchResponse{mHeader, &Command{AUTH_SWITCH_RESPONSE}, string(packet[5:])}
	}

	// Other packet can be identified by 5th byte value
	switch ctype {
	case 0x00: // OK_PACKET
		alen, affectedRows := decodeLengthEncodedInt(packet[5:])
		llen, lastInsertedID := decodeLengthEncodedInt(packet[5+alen:])
		offset := 5 + alen + llen
		statusFlags := judgeStatusFlags(packet[offset : offset+2])
		warnings := int(uint32(packet[offset+3]) | uint32(packet[offset+2])<<8)
		return OKPacket{mHeader, &Command{OK_PACKET}, affectedRows, lastInsertedID,
			statusFlags, warnings}
	case 0x01: // AUTH_SWITCH_REQUEST
		if plen > 1 {
			return AuthMoreData{mHeader, &Command{AUTH_MORE_DATA}, string(packet[5:])}
		}
	case 0x0a: // HANDSHAKE_V10
		if plen > 1 {
			zeroPos := plen
			for i := 5; i < plen+5; i++ {
				if packet[i] == 0x00 {
					zeroPos = i
					break
				}
			}
			offset := zeroPos + 1
			cid := int(uint32(packet[offset]) | uint32(packet[offset+1])<<8 | uint32(packet[offset+2])<<16 | uint32(packet[offset+3])<<24)
			authPluginDataPart1 := string(packet[offset+4 : offset+12])
			// packet[offset+12] is [00]
			cFlags := []CapacityFlag{}
			cFlags = append(cFlags, judgeLowerCapacityFlags(packet[offset+13:offset+15])...)
			flags := []GeneralPacketStatusFlag{}
			if offset+15 >= plen { // no more data
				return HandshakeV10{mHeader, &Command{HANDSHAKE_V10}, string(packet[5:zeroPos]),
					cid, authPluginDataPart1, 0, "",
					cFlags, UNKNOWN_CHARACTER_SET, flags, ""}
			}
			characterSet := judgeCharacterSet(packet[offset+15])
			flags = append(flags, judgeStatusFlags(packet[offset+16:offset+18])...)
			cFlags = append(cFlags, judgeUpperCapacityFlags(packet[offset+18:offset+20])...)
			lenAuthPluginData := 0
			if packet[offset+20] != 0x00 {
				lenAuthPluginData = int(packet[offset+20])
			}

			authPluginDataPart2 := ""
			l := maxInt(13, (lenAuthPluginData - 8))
			if lenAuthPluginData != 0 {
				authPluginDataPart2 = string(packet[offset+31 : offset+31+l])
			}
			authPluginName := string(packet[offset+31+l:])

			return HandshakeV10{mHeader, &Command{HANDSHAKE_V10}, string(packet[5:zeroPos]),
				cid, authPluginDataPart1, 0, authPluginDataPart2,
				cFlags, characterSet, flags, authPluginName}
		}
	case 0xfe:
		if plen == 1 { // OLD_AUTH_SWITCH_REQUEST
			return OldAuthSwitchRequest{mHeader, &Command{OLD_AUTH_SWITCH_REQUEST}}
		} else if plen == 5 { // EOF_PACKET
			warningsCount := int(uint32(packet[5]) | uint32(packet[6])<<8)
			flags := judgeStatusFlags(packet[7:9])
			return EOFPacket{mHeader, &Command{EOF_PACKET}, warningsCount, flags}
		} else { // AUTH_SWITCH_REQUEST (Anyway, I assume to not be OK_PACKET here
			for i, v := range packet[5:] {
				if v == 0x00 {
					return AuthSwitchRequest{mHeader, &Command{AUTH_SWITCH_REQUEST}, string(packet[5 : 6+i]), string(packet[6+i:])}
				}
			}
		}

	case 0xff: // ERR_PACKET
		errorCode := int(uint32(packet[5]) | uint32(packet[6])<<8)
		return ERRPacket{mHeader, &Command{ERR_PACKET}, errorCode,
			string(packet[7]), string(packet[8:14]), string(packet[14:])}
	default:
		// handshake response41
		if plen > 35 {
			allZero := true
			for _, p := range packet[13:36] {
				if p != 0x00 {
					allZero = false
				}
			}
			if allZero {
				// fmt.Println("[Connection] (Login Reqest) handshake response 41")
				return UnknownPacket{mHeader, &Command{UNKNOWN_PACKET}}
			}
		}

		// stringの場合の対処
		if ctype > 0x1f {
			// fmt.Println("[Connection] Auth plugin response")
			return UnknownPacket{mHeader, &Command{UNKNOWN_PACKET}}
		}
	}

	/*
	 * command Phase
	 */

	switch ctype {
	case 0x00: // COM_SLEEP
		if plen == 1 { //com_sleep
			return ComSleep{mHeader, &Command{COM_SLEEP}}
		}
	case 0x01: // COM_QUIT
		return ComQuit{mHeader, &Command{COM_QUIT}}
	case 0x02: // COM_INIT_DB
		if plen < 1 {
			return ComInitDb{mHeader, &Command{COM_INIT_DB}, ""}
		}
		return ComInitDb{mHeader, &Command{COM_INIT_DB}, string(packet[5 : 5+plen-1])}
	case 0x03: // COM_QUERY
		if sid < 1 { // stirng<EOF>
			return ComQuery{mHeader, &Command{COM_QUERY}, string(packet[5:])}
		} else {
			// com_query_response
		}
	case 0x04: // COM_FIELD_LIST
		// return 1 byte content COM_FIELD_LIST packet struct when plen == 1 ??
		if plen == 1 {
			return ComFieldList{mHeader, &Command{COM_FIELD_LIST}, "", ""}
		}
		nullPos := -1
		for i, v := range packet[5:] {
			if v == 0x00 {
				nullPos = i + 5
			}
		}
		return ComFieldList{mHeader, &Command{COM_FIELD_LIST}, string(packet[5:nullPos]), string(packet[nullPos+1:])}
	case 0x05: // COM_CREATE_DB
		return ComCreateDb{mHeader, &Command{COM_CREATE_DB}, string(packet[5:plen])}
	case 0x06: // COM_DROP_DB
		return ComDropDb{mHeader, &Command{COM_DROP_DB}, string(packet[5:plen])}
	case 0x07: // COM_REFRESH
		subCommand := packet[6]
		var subCommandType ComRefreshSubCommand
		subCommandType = COM_REFRESH_SUBCOMMAND_UNKNOWN
		switch subCommand {
		case 0x01:
			subCommandType = REFRESH_GRANT
		case 0x02:
			subCommandType = REFRESH_LOG
		case 0x04:
			subCommandType = REFRESH_TABLES
		case 0x08:
			subCommandType = REFRESH_HOSTS
		case 0x10:
			subCommandType = REFRESH_STATUS
		case 0x20:
			subCommandType = REFRESH_THREADS
		case 0x40:
			subCommandType = REFRESH_SLAVE
		case 0x80:
			subCommandType = REFRESH_MASTER
		}
		return ComRefresh{mHeader, &Command{COM_REFRESH}, subCommandType}
	case 0x08: // COM_SHUTDOWN
		if plen == 2 {
			subCommand := packet[6]
			var subCommandType ComShutdownSubCommand
			subCommandType = COM_SHUTDOWN_SUBCOMMAND_UNKNOWN
			switch subCommand {
			case 0x00:
				subCommandType = SHUTDOWN_DEFAULT
			case 0x01:
				subCommandType = SHUTDOWN_WAIT_CONNECTIONS
			case 0x02:
				subCommandType = SHUTDOWN_WAIT_TRANSACTIONS
			case 0x08:
				subCommandType = SHUTDOWN_WAIT_UPDATES
			case 0x10:
				subCommandType = SHUTDOWN_WAIT_ALL_BUFFERS
			case 0x11:
				subCommandType = SHUTDOWN_WAIT_CRITICAL_BUFFERS
			case 0xfe:
				subCommandType = KILL_QUERY
			case 0xff:
				subCommandType = KILL_CONNECTION
			}
			return ComShutdown{mHeader, &Command{COM_SHUTDOWN}, subCommandType}
		}
	case 0x09: // COM_STATISTICS
		return ComStatistics{mHeader, &Command{COM_STATISTICS}}
	case 0x0a: // COM_PROCESS_INFO
		return ComProcessInfo{mHeader, &Command{COM_PROCESS_INFO}}
	case 0x0b: // COM_CONNECT
		return ComConnect{mHeader, &Command{COM_CONNECT}}
	case 0x0c: // COM_PROCESS_KILL
		id := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		return ComProcessKill{mHeader, &Command{COM_PROCESS_KILL}, id}
	case 0x0d: // COM_DEBUG
		return ComDebug{mHeader, &Command{COM_DEBUG}}
	case 0x0e: // COM_PING
		return ComPing{mHeader, &Command{COM_PING}}
	case 0x0f: // COM_TIME
		return ComTime{mHeader, &Command{COM_TIME}}
	case 0x10: // COM_DELAYED_INSERT
		return ComDelayedInsert{mHeader, &Command{COM_DELAYED_INSERT}}
	case 0x11: // COM_CHANGE_USER
		// COM_CHANGE_USER is not completely supported...
		user := ""
		for i, v := range packet[5:] {
			if v == 0x00 {
				user = string(packet[5 : i+5])
			}
		}
		return ComChangeUser{mHeader, &Command{COM_CHANGE_USER}, user, 0, "",
			"", UNKNOWN_CHARACTER_SET, "", 0, nil}
	case 0x12: // COM_BINLOG_DUMP
		binlogpos := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		flag := packet[10] // packet[9], [10] is for flags
		sid := int(uint32(packet[11]) | uint32(packet[12])<<8 | uint32(packet[13])<<16 | uint32(packet[14])<<24)
		if flag == 0x01 {
			return ComBinlogDump{mHeader, &Command{COM_BINLOG_DUMP}, binlogpos, BINLOG_DUMP_NON_BLOCK, sid, string(packet[15:])}
		}
		return ComBinlogDump{mHeader, &Command{COM_BINLOG_DUMP}, binlogpos, COM_BINLOG_DUMP_FLAG_UNKONWN, sid, string(packet[15:])}
	case 0x13: // COM_TABLE_DUMP
		databaseLen := int(packet[5])
		tableLen := int(packet[5+databaseLen+1])
		return ComTableDump{mHeader, &Command{COM_TABLE_DUMP}, databaseLen, string(packet[6 : 6+databaseLen]), tableLen, string(packet[7+databaseLen:])}
	case 0x14: // COM_CONNECT_OUT
		return ComConnectOut{mHeader, &Command{COM_CONNECT_OUT}}
	case 0x15: // COM_REGISTER_SLAVE
		sid := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		slavesHostNameLen := int(packet[9])
		slavesUserLen := int(packet[9+slavesHostNameLen+1])
		slavesPasswordLen := int(packet[9+slavesHostNameLen+slavesUserLen+2])
		offset := slavesHostNameLen + slavesUserLen + slavesPasswordLen + 12
		slavesMySQLPort := int(uint32(packet[offset]) | uint32(packet[offset+1])<<8)
		replicationRank := int(uint32(packet[offset+2]) | uint32(packet[offset+3])<<8 | uint32(packet[offset+4])<<16 | uint32(offset+5)<<24)
		masterID := int(uint32(packet[offset+6]) | uint32(packet[offset+7])<<8 | uint32(packet[offset+8])<<16 | uint32(offset+9)<<24)
		return ComRegisterSlave{mHeader, &Command{COM_REGISTER_SLAVE},
			sid,
			slavesHostNameLen, string(packet[10 : 10+slavesHostNameLen]),
			slavesUserLen, string(packet[11+slavesHostNameLen : 11+slavesHostNameLen+slavesUserLen]),
			slavesPasswordLen, string(packet[12+slavesHostNameLen+slavesUserLen : 12+slavesHostNameLen+slavesUserLen+slavesPasswordLen]),
			slavesMySQLPort, replicationRank, masterID,
		}
	case 0x16: // COM_STMT_PREPARE
		return ComSTMTPrepare{mHeader, &Command{COM_STMT_PREPARE}, string(packet[5 : 4+plen])}
	case 0x17: // COM_STMT_EXECUTE
		// COM_STMT_EXECUTE is not completely supported...
		sid := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		var flags ComSTMTExecuteFlags
		flags = COM_STMT_EXECUTE_FLAG_UNKONWN
		switch packet[9] {
		case 0x00:
			flags = CURSOR_TYPE_NO_CURSOR
		case 0x01:
			flags = CURSOR_TYPE_READ_ONLY
		case 0x02:
			flags = CURSOR_TYPE_FOR_UPDATE
		case 0x04:
			flags = CURSOR_TYPE_SCROLLABLE
		}
		icnt := int(uint32(packet[10]) | uint32(packet[11])<<8 | uint32(packet[12])<<16 | uint32(packet[13])<<24)
		return ComSTMTExecute{mHeader, &Command{COM_STMT_EXECUTE}, sid, flags,
			icnt, "", 0, "", ""}
	case 0x18: // COM_STMT_SEND_LONG_DATA
		sid := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		pid := int(uint32(packet[9]) | uint32(packet[10])<<8)
		return ComSTMTSendLongData{mHeader, &Command{COM_STMT_SEND_LONG_DATA}, sid, pid, string(packet[11:])}
	case 0x19: // COM_STMT_CLOSE
		id := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		return ComSTMTClose{mHeader, &Command{COM_STMT_CLOSE}, id}
	case 0x1a: // COM_STMT_RESET
		id := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		return ComSTMTReset{mHeader, &Command{COM_STMT_RESET}, id}
	case 0x1b: // COM_SET_OPTION
		operation := packet[5]
		var operationFlag ComSetOptionOperation
		operationFlag = COM_SET_OPTION_OPERATION_UNKNOWN
		if operation == 0x00 {
			operationFlag = MYSQL_OPTION_MULTI_STATEMENTS_ON
		} else {
			operationFlag = MYSQL_OPTION_MULTI_STATEMENTS_OFF
		}
		return ComSetOption{mHeader, &Command{COM_SET_OPTION}, operationFlag}
	case 0x1c: // COM_STMT_FETCH
		sid := int(uint32(packet[5]) | uint32(packet[6])<<8 | uint32(packet[7])<<16 | uint32(packet[8])<<24)
		numRows := int(uint32(packet[9]) | uint32(packet[10])<<8 | uint32(packet[11])<<16 | uint32(packet[12])<<24)
		return ComSTMTFetch{mHeader, &Command{COM_STMT_FETCH}, sid, numRows}
	case 0x1d: // COM_DAEMON
		return ComDaemon{mHeader, &Command{COM_DAEMON}}
	case 0x1e: // COM_BINLOG_DUMP_GTID
		var flags ComBinlogDumpFlag = COM_BINLOG_DUMP_FLAG_UNKONWN
		switch packet[6] {
		case 0x01:
			flags = BINLOG_DUMP_NON_BLOCK
		case 0x02:
			flags = BINLOG_THROUGH_POSITION
		case 0x04:
			flags = BINLOG_THROUGH_GTID
		}
		sid := int(uint32(packet[7]) | uint32(packet[8])<<8 | uint32(packet[9])<<16 | uint32(packet[10])<<24)
		binlogFilenameLen := int(uint32(packet[11]) | uint32(packet[12])<<8 | uint32(packet[13])<<16 | uint32(packet[14])<<24)
		offset := 15 + binlogFilenameLen
		binlogPos := int(uint32(packet[offset]) | uint32(packet[offset+1])<<8 | uint32(packet[offset+2])<<16 | uint32(packet[offset+3])<<24 |
			uint32(packet[offset+4])<<32 | uint32(packet[offset+5])<<40 | uint32(packet[offset+6])<<48 | uint32(packet[offset+7])<<56)
		dataSize := 0
		if plen > 19+binlogFilenameLen {
			dataSize = int(uint32(packet[offset+8]) | uint32(packet[offset+9])<<8 | uint32(packet[offset+10])<<16 | uint32(packet[offset+11])<<24)
			return ComBinlogDumpGTID{mHeader, &Command{COM_BINLOG_DUMP_GTID}, flags, sid,
				binlogFilenameLen, string(packet[15:offset]), binlogPos, dataSize, string(packet[offset+12:])}
		}
		return ComBinlogDumpGTID{mHeader, &Command{COM_BINLOG_DUMP_GTID}, flags, sid,
			binlogFilenameLen, string(packet[15:offset]), binlogPos, dataSize, ""}
	case 0x1f: // COM_RESET_CONNECTION
		return ComResetConnection{mHeader, &Command{COM_RESET_CONNECTION}}

	}

	return UnknownPacket{mHeader, &Command{UNKNOWN_PACKET}}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
