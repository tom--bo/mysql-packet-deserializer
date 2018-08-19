package mysqlpacket

/*
 * Desirialize method
 */

func DeserializePacket(packet []byte) []IMySQLPacket {
	plen := len(packet)
	nowPos := 0
	mysqlPackets := []IMySQLPacket{}

	for plen-nowPos > 0 {
		pktLen := int(uint32(packet[nowPos]) | uint32(packet[nowPos+1])<<8 | uint32(packet[nowPos+2])<<16)

		mysqlPackets = append(mysqlPackets, mapPacket(pktLen, packet[nowPos:nowPos+(4+pktLen)]))
		nowPos += 4 + pktLen

		// stop processing multiple MySQL packet
		break
	}

	return mysqlPackets
}

func judgeCapacityFlags(packets []byte) []CapacityFlag {
	// ??
	return []CapacityFlag{UNKNOWN_CAPACITY_FLAG}
}

func judgeCharacterSet(cset byte) CharacterSet {
	// ??
	return UNKNOWN_CHARACTER_SET
}

func judgeStatusFlags(packet []byte) []GeneralPacketStatusFlag {
	// ??
	return []GeneralPacketStatusFlag{}
}

func judgeLengthEncodedInt([]byte) (int, int) {
	return 0, 0 // ??
}

func mapPacket(plen int, packet []byte) IMySQLPacket {
	sid := int(packet[3])
	ctype := packet[4]
	mHeader := MySQLHeader{uint32(plen), uint8(sid)}

	/*
	 * general response or connection phase packet
	 */

	// At first, judge no header packet (Header + 9~31 byte are all 00)
	// HandshakeResponse41 or SSLRequest
	if plen > 35 {
		allZero := true
		for _, p := range packet[13:36] {
			if p != 0x00 {
				allZero = false
			}
		}
		if allZero {
			flags := judgeCapacityFlags(packet[5:9])
			maxPacketSize := int(uint32(packet[10]) | uint32(packet[11])<<8 | uint32(packet[12])<<16 | uint32(packet[13])<<24)
			cset := judgeCharacterSet(packet[14])
			if plen <= 36 { // SSL_REQUEST
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
		affectedRows, alen := judgeLengthEncodedInt(packet[6:])
		lastInsertedID, llen := judgeLengthEncodedInt(packet[6+alen:])
		offset := 6 + alen + llen
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
			return HandshakeV10{mHeader, &Command{HANDSHAKE_V10}, string(packet[5:zeroPos]),
				cid, string(packet[offset+4 : offset+12]), packet[offset+13 : offset+15]}
		}
	case 0xfe:
		if plen == 1 { // OLD_AUTH_SWITCH_REQUEST
			return OldAuthSwitchRequest{mHeader, &Command{OLD_AUTH_SWITCH_REQUEST}}
		} else if plen == 5 { // EOF_PACKET
			flags := judgeStatusFlags(packet[7:9])
			warningsCount := int(uint32(packet[6]) | uint32(packet[7])<<8)
			return EOFPacket{mHeader, &Command{EOF_PACKET}, warningsCount, flags}
		} else { // AUTH_SWITCH_REQUEST (Anyway, I assume to not be OK_PACKET here
			for i, v := range packet[5:] {
				if v == 0x00 {
					return AuthSwitchRequest{mHeader, &Command{AUTH_SWITCH_REQUEST}, string(packet[5 : 6+i]), string(packet[6+i:])}
				}
			}
		}

	case 0xff: // ERR_PACKET
		errorCode := int(uint32(packet[6]) | uint32(packet[5])<<8)
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
		return ComInitDb{mHeader, &Command{COM_INIT_DB}, string(packet[5:plen])}
	case 0x03: // COM_QUERY
		if sid < 1 { // stirng<EOF>
			return ComQuery{mHeader, &Command{COM_QUERY}, string(packet[5:])}
		} else {
			// response
		}
	case 0x04: // COM_FIELD_LIST
		// return 1 byte content COM_FIELD_LIST packet struct when plen == 1 ??
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
		return ComSTMTPrepare{mHeader, &Command{COM_STMT_PREPARE}, string(packet[5:plen])}
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
