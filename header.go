package mysqlpacket

type CommandType string

const (
	// Connection Phase Packet
	HANDSHAKE_V10           CommandType = "HANDSHAKE_V10"
	HANDSHAKE_RESPONSE41                = "HANDSHAKE_RESPONSE41"
	SSL_REQUEST                         = "SSL_REQUEST"
	AUTH_SWITCH_REQUEST                 = "AUTH_SWITCH_REQUEST"
	OLD_AUTH_SWITCH_REQUEST             = "OLD_AUTH_SWITCH_REQUEST"
	AUTH_SWITCH_RESPONSE                = "AUTH_SWITCH_RESPONSE"
	AUTH_MORE_DATA                      = "AUTH_MORE_DATA"
	// General Response Packet
	OK_PACKET  = "OK_PACKET"
	ERR_PACKET = "ERR_PACKET"
	EOF_PACKET = "EOF_PACKET"
	// Command Phase Packet
	COM_SLEEP               = "COM_SLEEP"
	COM_QUIT                = "COM_QUIT"
	COM_INIT_DB             = "COM_INIT_DB"
	COM_QUERY               = "COM_QUERY"
	COM_FIELD_LIST          = "COM_FIELD_LIST" // Deprecated
	COM_CREATE_DB           = "COM_CREATE_DB"  // Currenty refused (5.x?)
	COM_DROP_DB             = "COM_DROP_DB"    // Currenty refused (5.x?)
	COM_REFRESH             = "COM_REFRESH"    // Deprecated
	COM_SHUTDOWN            = "COM_SHUTDOWN"
	COM_STATISTICS          = "COM_STATISTICS"
	COM_PROCESS_INFO        = "COM_PROCESS_INFO" // Deprecated
	COM_CONNECT             = "COM_CONNECT"
	COM_PROCESS_KILL        = "COM_PROCESS_KILL" // Deprecated
	COM_DEBUG               = "COM_DEBUG"
	COM_PING                = "COM_PING"
	COM_TIME                = "COM_TIME"           // Currenty refused (5.x?)
	COM_DELAYED_INSERT      = "COM_DELAYED_INSERT" // Functionality removed (8.0?)
	COM_CHANGE_USER         = "COM_CHANGE_USER"
	COM_BINLOG_DUMP         = "COM_BINLOG_DUMP"
	COM_TABLE_DUMP          = "COM_TABLE_DUMP"
	COM_CONNECT_OUT         = "COM_CONNECT_OUT"
	COM_REGISTER_SLAVE      = "COM_REGISTER_SLAVE"
	COM_STMT_PREPARE        = "COM_STMT_PREPARE"
	COM_STMT_EXECUTE        = "COM_STMT_EXECUTE"
	COM_STMT_SEND_LONG_DATA = "COM_STMT_SEND_LONG_DATA"
	COM_STMT_CLOSE          = "COM_STMT_CLOSE"
	COM_STMT_RESET          = "COM_STMT_RESET"
	COM_SET_OPTION          = "COM_SET_OPTION"
	COM_STMT_FETCH          = "COM_STMT_FETCH"
	COM_DAEMON              = "COM_DAEMON"
	COM_BINLOG_DUMP_GTID    = "COM_BINLOG_DUMP_GTID"
	COM_RESET_CONNECTION    = "COM_RESET_CONNECTION"
	// Unknown or Not Supported Packet
	UNKNOWN_PACKET = "UNKNOWN_PACKET"
)

type CharacterSet string

const (
	DEC8_COLLATE_DEC8_SWEDISH_CI           CharacterSet = "DEC8_COLLATE_DEC8_SWEDISH_CI"
	CP850_COLLATE_CP850_GENERAL_CI                      = "CP850_COLLATE_CP850_GENERAL_CI"
	LATIN1_COLLATE_LATIN1_GERMAN1_CI                    = "LATIN1_COLLATE_LATIN1_GERMAN1_CI"
	HP8_COLLATE_HP8_ENGLISH_CI                          = "HP8_COLLATE_HP8_ENGLISH_CI"
	KOI8R_COLLATE_KOI8R_GENERAL_CI                      = "KOI8R_COLLATE_KOI8R_GENERAL_CI"
	LATIN1_COLLATE_LATIN1_SWEDISH_CI                    = "LATIN1_COLLATE_LATIN1_SWEDISH_CI"
	LATIN2_COLLATE_LATIN2_GENERAL_CI                    = "LATIN2_COLLATE_LATIN2_GENERAL_CI"
	SWE7_COLLATE_SWE7_SWEDISH_CI                        = "SWE7_COLLATE_SWE7_SWEDISH_CI"
	ASCII_COLLATE_ASCII_GENERAL_CI                      = "ASCII_COLLATE_ASCII_GENERAL_CI"
	CP1251_COLLATE_CP1251_BULGARIAN_CI                  = "CP1251_COLLATE_CP1251_BULGARIAN_CI"
	LATIN1_COLLATE_LATIN1_DANISH_CI                     = "LATIN1_COLLATE_LATIN1_DANISH_CI"
	HEBREW_COLLATE_HEBREW_GENERAL_CI                    = "HEBREW_COLLATE_HEBREW_GENERAL_CI"
	LATIN7_COLLATE_LATIN7_ESTONIAN_CS                   = "LATIN7_COLLATE_LATIN7_ESTONIAN_CS"
	LATIN2_COLLATE_LATIN2_HUNGARIAN_CI                  = "LATIN2_COLLATE_LATIN2_HUNGARIAN_CI"
	KOI8U_COLLATE_KOI8U_GENERAL_CI                      = "KOI8U_COLLATE_KOI8U_GENERAL_CI"
	CP1251_COLLATE_CP1251_UKRAINIAN_CI                  = "CP1251_COLLATE_CP1251_UKRAINIAN_CI"
	GREEK_COLLATE_GREEK_GENERAL_CI                      = "GREEK_COLLATE_GREEK_GENERAL_CI"
	CP1250_COLLATE_CP1250_GENERAL_CI                    = "CP1250_COLLATE_CP1250_GENERAL_CI"
	LATIN2_COLLATE_LATIN2_CROATIAN_CI                   = "LATIN2_COLLATE_LATIN2_CROATIAN_CI"
	CP1257_COLLATE_CP1257_LITHUANIAN_CI                 = "CP1257_COLLATE_CP1257_LITHUANIAN_CI"
	LATIN5_COLLATE_LATIN5_TURKISH_CI                    = "LATIN5_COLLATE_LATIN5_TURKISH_CI"
	LATIN1_COLLATE_LATIN1_GERMAN2_CI                    = "LATIN1_COLLATE_LATIN1_GERMAN2_CI"
	ARMSCII8_COLLATE_ARMSCII8_GENERAL_CI                = "ARMSCII8_COLLATE_ARMSCII8_GENERAL_CI"
	UTF8_COLLATE_UTF8_GENERAL_CI                        = "UTF8_COLLATE_UTF8_GENERAL_CI"
	CP866_COLLATE_CP866_GENERAL_CI                      = "CP866_COLLATE_CP866_GENERAL_CI"
	KEYBCS2_COLLATE_KEYBCS2_GENERAL_CI                  = "KEYBCS2_COLLATE_KEYBCS2_GENERAL_CI"
	MACCE_COLLATE_MACCE_GENERAL_CI                      = "MACCE_COLLATE_MACCE_GENERAL_CI"
	MACROMAN_COLLATE_MACROMAN_GENERAL_CI                = "MACROMAN_COLLATE_MACROMAN_GENERAL_CI"
	CP852_COLLATE_CP852_GENERAL_CI                      = "CP852_COLLATE_CP852_GENERAL_CI"
	LATIN7_COLLATE_LATIN7_GENERAL_CI                    = "LATIN7_COLLATE_LATIN7_GENERAL_CI"
	LATIN7_COLLATE_LATIN7_GENERAL_CS                    = "LATIN7_COLLATE_LATIN7_GENERAL_CS"
	MACCE_COLLATE_MACCE_BIN                             = "MACCE_COLLATE_MACCE_BIN"
	CP1250_COLLATE_CP1250_CROATIAN_CI                   = "CP1250_COLLATE_CP1250_CROATIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_GENERAL_CI                  = "UTF8MB4_COLLATE_UTF8MB4_GENERAL_CI"
	UTF8MB4_COLLATE_UTF8MB4_BIN                         = "UTF8MB4_COLLATE_UTF8MB4_BIN"
	LATIN1_COLLATE_LATIN1_BIN                           = "LATIN1_COLLATE_LATIN1_BIN"
	LATIN1_COLLATE_LATIN1_GENERAL_CI                    = "LATIN1_COLLATE_LATIN1_GENERAL_CI"
	LATIN1_COLLATE_LATIN1_GENERAL_CS                    = "LATIN1_COLLATE_LATIN1_GENERAL_CS"
	CP1251_COLLATE_CP1251_BIN                           = "CP1251_COLLATE_CP1251_BIN"
	CP1251_COLLATE_CP1251_GENERAL_CI                    = "CP1251_COLLATE_CP1251_GENERAL_CI"
	CP1251_COLLATE_CP1251_GENERAL_CS                    = "CP1251_COLLATE_CP1251_GENERAL_CS"
	MACROMAN_COLLATE_MACROMAN_BIN                       = "MACROMAN_COLLATE_MACROMAN_BIN"
	CP1256_COLLATE_CP1256_GENERAL_CI                    = "CP1256_COLLATE_CP1256_GENERAL_CI"
	CP1257_COLLATE_CP1257_BIN                           = "CP1257_COLLATE_CP1257_BIN"
	CP1257_COLLATE_CP1257_GENERAL_CI                    = "CP1257_COLLATE_CP1257_GENERAL_CI"
	BINARY_COLLATE_BINARY                               = "BINARY_COLLATE_BINARY"
	ARMSCII8_COLLATE_ARMSCII8_BIN                       = "ARMSCII8_COLLATE_ARMSCII8_BIN"
	ASCII_COLLATE_ASCII_BIN                             = "ASCII_COLLATE_ASCII_BIN"
	CP1250_COLLATE_CP1250_BIN                           = "CP1250_COLLATE_CP1250_BIN"
	CP1256_COLLATE_CP1256_BIN                           = "CP1256_COLLATE_CP1256_BIN"
	CP866_COLLATE_CP866_BIN                             = "CP866_COLLATE_CP866_BIN"
	DEC8_COLLATE_DEC8_BIN                               = "DEC8_COLLATE_DEC8_BIN"
	GREEK_COLLATE_GREEK_BIN                             = "GREEK_COLLATE_GREEK_BIN"
	HEBREW_COLLATE_HEBREW_BIN                           = "HEBREW_COLLATE_HEBREW_BIN"
	HP8_COLLATE_HP8_BIN                                 = "HP8_COLLATE_HP8_BIN"
	KEYBCS2_COLLATE_KEYBCS2_BIN                         = "KEYBCS2_COLLATE_KEYBCS2_BIN"
	KOI8R_COLLATE_KOI8R_BIN                             = "KOI8R_COLLATE_KOI8R_BIN"
	KOI8U_COLLATE_KOI8U_BIN                             = "KOI8U_COLLATE_KOI8U_BIN"
	LATIN2_COLLATE_LATIN2_BIN                           = "LATIN2_COLLATE_LATIN2_BIN"
	LATIN5_COLLATE_LATIN5_BIN                           = "LATIN5_COLLATE_LATIN5_BIN"
	LATIN7_COLLATE_LATIN7_BIN                           = "LATIN7_COLLATE_LATIN7_BIN"
	CP850_COLLATE_CP850_BIN                             = "CP850_COLLATE_CP850_BIN"
	CP852_COLLATE_CP852_BIN                             = "CP852_COLLATE_CP852_BIN"
	SWE7_COLLATE_SWE7_BIN                               = "SWE7_COLLATE_SWE7_BIN"
	UTF8_COLLATE_UTF8_BIN                               = "UTF8_COLLATE_UTF8_BIN"
	GEOSTD8_COLLATE_GEOSTD8_GENERAL_CI                  = "GEOSTD8_COLLATE_GEOSTD8_GENERAL_CI"
	GEOSTD8_COLLATE_GEOSTD8_BIN                         = "GEOSTD8_COLLATE_GEOSTD8_BIN"
	LATIN1_COLLATE_LATIN1_SPANISH_CI                    = "LATIN1_COLLATE_LATIN1_SPANISH_CI"
	CP1250_COLLATE_CP1250_POLISH_CI                     = "CP1250_COLLATE_CP1250_POLISH_CI"
	UTF8_COLLATE_UTF8_UNICODE_CI                        = "UTF8_COLLATE_UTF8_UNICODE_CI"
	UTF8_COLLATE_UTF8_ICELANDIC_CI                      = "UTF8_COLLATE_UTF8_ICELANDIC_CI"
	UTF8_COLLATE_UTF8_LATVIAN_CI                        = "UTF8_COLLATE_UTF8_LATVIAN_CI"
	UTF8_COLLATE_UTF8_ROMANIAN_CI                       = "UTF8_COLLATE_UTF8_ROMANIAN_CI"
	UTF8_COLLATE_UTF8_SLOVENIAN_CI                      = "UTF8_COLLATE_UTF8_SLOVENIAN_CI"
	UTF8_COLLATE_UTF8_POLISH_CI                         = "UTF8_COLLATE_UTF8_POLISH_CI"
	UTF8_COLLATE_UTF8_ESTONIAN_CI                       = "UTF8_COLLATE_UTF8_ESTONIAN_CI"
	UTF8_COLLATE_UTF8_SPANISH_CI                        = "UTF8_COLLATE_UTF8_SPANISH_CI"
	UTF8_COLLATE_UTF8_SWEDISH_CI                        = "UTF8_COLLATE_UTF8_SWEDISH_CI"
	UTF8_COLLATE_UTF8_TURKISH_CI                        = "UTF8_COLLATE_UTF8_TURKISH_CI"
	UTF8_COLLATE_UTF8_CZECH_CI                          = "UTF8_COLLATE_UTF8_CZECH_CI"
	UTF8_COLLATE_UTF8_DANISH_CI                         = "UTF8_COLLATE_UTF8_DANISH_CI"
	UTF8_COLLATE_UTF8_LITHUANIAN_CI                     = "UTF8_COLLATE_UTF8_LITHUANIAN_CI"
	UTF8_COLLATE_UTF8_SLOVAK_CI                         = "UTF8_COLLATE_UTF8_SLOVAK_CI"
	UTF8_COLLATE_UTF8_SPANISH2_CI                       = "UTF8_COLLATE_UTF8_SPANISH2_CI"
	UTF8_COLLATE_UTF8_ROMAN_CI                          = "UTF8_COLLATE_UTF8_ROMAN_CI"
	UTF8_COLLATE_UTF8_PERSIAN_CI                        = "UTF8_COLLATE_UTF8_PERSIAN_CI"
	UTF8_COLLATE_UTF8_ESPERANTO_CI                      = "UTF8_COLLATE_UTF8_ESPERANTO_CI"
	UTF8_COLLATE_UTF8_HUNGARIAN_CI                      = "UTF8_COLLATE_UTF8_HUNGARIAN_CI"
	UTF8_COLLATE_UTF8_SINHALA_CI                        = "UTF8_COLLATE_UTF8_SINHALA_CI"
	UTF8_COLLATE_UTF8_GERMAN2_CI                        = "UTF8_COLLATE_UTF8_GERMAN2_CI"
	UTF8_COLLATE_UTF8_CROATIAN_CI                       = "UTF8_COLLATE_UTF8_CROATIAN_CI"
	UTF8_COLLATE_UTF8_UNICODE_520_CI                    = "UTF8_COLLATE_UTF8_UNICODE_520_CI"
	UTF8_COLLATE_UTF8_VIETNAMESE_CI                     = "UTF8_COLLATE_UTF8_VIETNAMESE_CI"
	UTF8_COLLATE_UTF8_GENERAL_MYSQL500_CI               = "UTF8_COLLATE_UTF8_GENERAL_MYSQL500_CI"
	UTF8MB4_COLLATE_UTF8MB4_UNICODE_CI                  = "UTF8MB4_COLLATE_UTF8MB4_UNICODE_CI"
	UTF8MB4_COLLATE_UTF8MB4_ICELANDIC_CI                = "UTF8MB4_COLLATE_UTF8MB4_ICELANDIC_CI"
	UTF8MB4_COLLATE_UTF8MB4_LATVIAN_CI                  = "UTF8MB4_COLLATE_UTF8MB4_LATVIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_ROMANIAN_CI                 = "UTF8MB4_COLLATE_UTF8MB4_ROMANIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_SLOVENIAN_CI                = "UTF8MB4_COLLATE_UTF8MB4_SLOVENIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_POLISH_CI                   = "UTF8MB4_COLLATE_UTF8MB4_POLISH_CI"
	UTF8MB4_COLLATE_UTF8MB4_ESTONIAN_CI                 = "UTF8MB4_COLLATE_UTF8MB4_ESTONIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_SPANISH_CI                  = "UTF8MB4_COLLATE_UTF8MB4_SPANISH_CI"
	UTF8MB4_COLLATE_UTF8MB4_SWEDISH_CI                  = "UTF8MB4_COLLATE_UTF8MB4_SWEDISH_CI"
	UTF8MB4_COLLATE_UTF8MB4_TURKISH_CI                  = "UTF8MB4_COLLATE_UTF8MB4_TURKISH_CI"
	UTF8MB4_COLLATE_UTF8MB4_CZECH_CI                    = "UTF8MB4_COLLATE_UTF8MB4_CZECH_CI"
	UTF8MB4_COLLATE_UTF8MB4_DANISH_CI                   = "UTF8MB4_COLLATE_UTF8MB4_DANISH_CI"
	UTF8MB4_COLLATE_UTF8MB4_LITHUANIAN_CI               = "UTF8MB4_COLLATE_UTF8MB4_LITHUANIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_SLOVAK_CI                   = "UTF8MB4_COLLATE_UTF8MB4_SLOVAK_CI"
	UTF8MB4_COLLATE_UTF8MB4_SPANISH2_CI                 = "UTF8MB4_COLLATE_UTF8MB4_SPANISH2_CI"
	UTF8MB4_COLLATE_UTF8MB4_ROMAN_CI                    = "UTF8MB4_COLLATE_UTF8MB4_ROMAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_PERSIAN_CI                  = "UTF8MB4_COLLATE_UTF8MB4_PERSIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_ESPERANTO_CI                = "UTF8MB4_COLLATE_UTF8MB4_ESPERANTO_CI"
	UTF8MB4_COLLATE_UTF8MB4_HUNGARIAN_CI                = "UTF8MB4_COLLATE_UTF8MB4_HUNGARIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_SINHALA_CI                  = "UTF8MB4_COLLATE_UTF8MB4_SINHALA_CI"
	UTF8MB4_COLLATE_UTF8MB4_GERMAN2_CI                  = "UTF8MB4_COLLATE_UTF8MB4_GERMAN2_CI"
	UTF8MB4_COLLATE_UTF8MB4_CROATIAN_CI                 = "UTF8MB4_COLLATE_UTF8MB4_CROATIAN_CI"
	UTF8MB4_COLLATE_UTF8MB4_UNICODE_520_CI              = "UTF8MB4_COLLATE_UTF8MB4_UNICODE_520_CI"
	UTF8MB4_COLLATE_UTF8MB4_VIETNAMESE_CI               = "UTF8MB4_COLLATE_UTF8MB4_VIETNAMESE_CI"
	UNKNOWN_CHARACTER_SET                               = "UNKNOWN_CHARACTER_SET"
)

type CapacityFlag string

const (
	CLIENT_LONG_PASSWORD                  CapacityFlag = "CLIENT_LONG_PASSWORD"
	CLIENT_FOUND_ROWS                                  = "CLIENT_FOUND_ROWS"
	CLIENT_LONG_FLAG                                   = "CLIENT_LONG_FLAG"
	CLIENT_CONNECT_WITH_DB                             = "CLIENT_CONNECT_WITH_DB"
	CLIENT_NO_SCHEMA                                   = "CLIENT_NO_SCHEMA"
	CLIENT_COMPRESS                                    = "CLIENT_COMPRESS"
	CLIENT_ODBC                                        = "CLIENT_ODBC"
	CLIENT_LOCAL_FILES                                 = "CLIENT_LOCAL_FILES"
	CLIENT_IGNORE_SPACE                                = "CLIENT_IGNORE_SPACE"
	CLIENT_41                                          = "CLIENT_41"
	CLIENT_INTERACTIVE                                 = "CLIENT_INTERACTIVE"
	CLIENT_SSL                                         = "CLIENT_SSL"
	CLIENT_IGNORE_SIGPIPE                              = "CLIENT_IGNORE_SIGPIPE"
	CLIENT_TRANSACTIONS                                = "CLIENT_TRANSACTIONS"
	CLIENT_RESERVED                                    = "CLIENT_RESERVED"
	CLIENT_SECURE_CONNECTION                           = "CLIENT_SECURE_CONNECTION"
	CLIENT_MULTI_STATEMENTS                            = "CLIENT_MULTI_STATEMENTS"
	CLIENT_MULTI_RESULTS                               = "CLIENT_MULTI_RESULTS"
	CLIENT_PS_MULTI_RESULTS                            = "CLIENT_PS_MULTI_RESULTS"
	CLIENT_PLUGIN_AUTH                                 = "CLIENT_PLUGIN_AUTH"
	CLIENT_CONNECT_ATTRS                               = "CLIENT_CONNECT_ATTRS"
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA              = "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA"
	CLIENT_CAN_HANDLE_EXPIRED_PASSWORD                 = "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS"
	CLIENT_SESSION_TRACK                               = "CLIENT_SESSION_TRACK"
	CLIENT_DEPRECATE_EOF                               = "CLIENT_DEPRECATE_EOF"
)

type GeneralPacketStatusFlag string

const (
	SERVER_STATUS_IN_TRANS           GeneralPacketStatusFlag = "SERVER_STATUS_IN_TRANS"
	SERVER_STATUS_AUTOCOMMIT                                 = "SERVER_STATUS_AUTOCOMMIT"
	SERVER_MORE_RESULTS_EXISTS                               = "SERVER_MORE_RESULTS_EXISTS"
	SERVER_STATUS_NO_GOOD_INDEX_USED                         = "SERVER_STATUS_NO_GOOD_INDEX_USED"
	SERVER_STATUS_NO_INDEX_USED                              = "SERVER_STATUS_NO_INDEX_USED"
	SERVER_STATUS_CURSOR_EXISTS                              = "SERVER_STATUS_CURSOR_EXISTS"
	SERVER_STATUS_LAST_ROW_SENT                              = "SERVER_STATUS_LAST_ROW_SENT"
	// byte boundary
	SERVER_STATUS_DB_DROPPED           = "SERVER_STATUS_DB_DROPPED"
	SERVER_STATUS_NO_BACKSLASH_ESCAPES = "SERVER_STATUS_NO_BACKSLASH_ESCAPES"
	SERVER_STATUS_METADATA_CHANGE      = "SERVER_STATUS_METADATA_CHANGE"
	SERVER_QUERY_WAS_SLOW              = "SERVER_QUERY_WAS_SLOW"
	SERVER_PS_OUT_PARAMS               = "SERVER_PS_OUT_PARAMS"
	SERVER_STATUS_IN_TRANS_READONLY    = "SERVER_STATUS_IN_TRANS_READONLY"
	SERVER_SESSION_STATE_CHANGED       = "SERVER_SESSION_STATE_CHANGED"
)

type ComRefreshSubCommand string

const (
	REFRESH_GRANT                  ComRefreshSubCommand = "REFRESH_GRANT"
	REFRESH_LOG                                         = "REFRESH_LOG"
	REFRESH_TABLES                                      = "REFRESH_TABLES"
	REFRESH_HOSTS                                       = "REFRESH_HOSTS"
	REFRESH_STATUS                                      = "REFRESH_STATUS"
	REFRESH_THREADS                                     = "REFRESH_THREADS"
	REFRESH_SLAVE                                       = "REFRESH_SLAVE"
	REFRESH_MASTER                                      = "REFRESH_MASTER"
	COM_REFRESH_SUBCOMMAND_UNKNOWN                      = "COM_REFRESH_SUBCOMMAND_UNKNOWN"
)

type ComShutdownSubCommand string

const (
	SHUTDOWN_DEFAULT                ComShutdownSubCommand = "SHUTDOWN_DEFAULT"
	SHUTDOWN_WAIT_CONNECTIONS                             = "SHUTDOWN_WAIT_CONNECTIONS"
	SHUTDOWN_WAIT_TRANSACTIONS                            = "SHUTDOWN_WAIT_TRANSACTIONS"
	SHUTDOWN_WAIT_UPDATES                                 = "SHUTDOWN_WAIT_UPDATES"
	SHUTDOWN_WAIT_ALL_BUFFERS                             = "SHUTDOWN_WAIT_ALL_BUFFERS"
	SHUTDOWN_WAIT_CRITICAL_BUFFERS                        = "SHUTDOWN_WAIT_CRITICAL_BUFFERS"
	KILL_QUERY                                            = "KILL_QUERY"
	KILL_CONNECTION                                       = "KILL_CONNECTION"
	COM_SHUTDOWN_SUBCOMMAND_UNKNOWN                       = "COM_SHUTDOWN_SUBCOMMAND_UNKNOWN"
)

type ComSetOptionOperation string

const (
	MYSQL_OPTION_MULTI_STATEMENTS_ON  ComSetOptionOperation = "MYSQL_OPTION_MULTI_STATEMENTS_ON"
	MYSQL_OPTION_MULTI_STATEMENTS_OFF                       = "MYSQL_OPTION_MULTI_STATEMENTS_OFF"
	COM_SET_OPTION_OPERATION_UNKNOWN                        = "COM_SET_OPTION_OPERATION_UNKNOWN"
)

type ComBinlogDumpFlag string

// This type is used as ComBinlogDumpGTIDFlags also

const (
	BINLOG_DUMP_NON_BLOCK        ComBinlogDumpFlag = "BINLOG_DUMP_NON_BLOCK"
	BINLOG_THROUGH_POSITION                        = "BINLOG_THROUGH_POSITION"
	BINLOG_THROUGH_GTID                            = "BINLOG_THROUGH_GTID"
	COM_BINLOG_DUMP_FLAG_UNKONWN                   = "COM_BINLOG_DUMP_FLAG_UNKONWN"
)

type ComSTMTExecuteFlags string

const (
	CURSOR_TYPE_NO_CURSOR         ComSTMTExecuteFlags = "CURSOR_TYPE_NO_CURSOR"
	CURSOR_TYPE_READ_ONLY                             = "CURSOR_TYPE_READ_ONLY"
	CURSOR_TYPE_FOR_UPDATE                            = "CURSOR_TYPE_FOR_UPDATE"
	CURSOR_TYPE_SCROLLABLE                            = "CURSOR_TYPE_SCROLLABLE"
	COM_STMT_EXECUTE_FLAG_UNKONWN                     = "COM_STMT_EXECUTE_FLAG_UNKONWN"
)

type ColumnType string

const (
	TYPE_DECIMAL     ColumnType = "TYPE_DECIMAL"
	TYPE_TINY                   = "TYPE_TINY"
	TYPE_SHORT                  = "TYPE_SHORT"
	TYPE_LONG                   = "TYPE_LONG"
	TYPE_FLOAT                  = "TYPE_FLOAT"
	TYPE_DOUBLE                 = "TYPE_DOUBLE"
	TYPE_NULL                   = "TYPE_NULL"
	TYPE_TIMESTAMP              = "TYPE_TIMESTAMP"
	TYPE_LONGLONG               = "TYPE_LONGLONG"
	TYPE_INT24                  = "TYPE_INT24"
	TYPE_DATE                   = "TYPE_DATE"
	TYPE_TIME                   = "TYPE_TIME"
	TYPE_DATETIME               = "TYPE_DATETIME"
	TYPE_YEAR                   = "TYPE_YEAR"
	TYPE_NEWDATE                = "TYPE_NEWDATE"
	TYPE_VARCHAR                = "TYPE_VARCHAR"
	TYPE_BIT                    = "TYPE_BIT"
	TYPE_TIMESTAMP2             = "TYPE_TIMESTAMP2"
	TYPE_DATETIME2              = "TYPE_DATETIME2"
	TYPE_TIME2                  = "TYPE_TIME2"
	TYPE_NEWDECIMAL             = "TYPE_NEWDECIMAL"
	TYPE_ENUM                   = "TYPE_ENUM"
	TYPE_SET                    = "TYPE_SET"
	TYPE_TINY_BLOB              = "TYPE_TINY_BLOB"
	TYPE_MEDIUM_BLOB            = "TYPE_MEDIUM_BLOB"
	TYPE_LONG_BLOB              = "TYPE_LONG_BLOB"
	TYPE_BLOB                   = "TYPE_BLOB"
	TYPE_VAR_STRING             = "TYPE_VAR_STRING"
	TYPE_STRING                 = "TYPE_STRING"
	TYPE_GEOMETRY               = "TYPE_GEOMETRY"
	TYPE_UNKNOWN                = "TYPE_UNKNOWN"
)

/*
 * MySQL Common Header
 */

type IMySQLPacket interface {
	GetCommandType() CommandType
}

type Command struct {
	cmdType CommandType
}

func (c *Command) GetCommandType() CommandType {
	return c.cmdType
}

type MySQLHeader struct {
	PayloadLength uint32
	SequenceID    uint8
}

/*
 * Initial Handshake Packet
 */

type HandshakeV10 struct {
	Header MySQLHeader
	*Command
	ServerVersion          string
	ConnectionID           int
	AuthPluginDataPart1    string
	LengthOfAuthPluginData int
	AuthPluginDataPart2    string
	CapacityFlag           []CapacityFlag
	CharacterSet           CharacterSet
	StatusFlags            []GeneralPacketStatusFlag
	AuthPluginName         string
}

type HandshakeResponse41 struct {
	Header MySQLHeader
	*Command
	CapacityFlag  []CapacityFlag
	MaxPacketSize int
	CharacterSet  CharacterSet
}

type SSLRequest struct {
	Header MySQLHeader
	*Command
	CapacityFlag  []CapacityFlag
	MaxPacketSize int
	CharacterSet  CharacterSet
}

type AuthSwitchRequest struct {
	Header MySQLHeader
	*Command
	PluginName     string
	AuthPluginData string
}

type OldAuthSwitchRequest struct {
	Header MySQLHeader
	*Command
}

type AuthSwitchResponse struct {
	Header MySQLHeader
	*Command
	AuthPluginResponse string
}

type AuthMoreData struct {
	Header MySQLHeader
	*Command
	PluginData string
}

/*
 * General Response Packet
 */

type OKPacket struct {
	Header MySQLHeader
	*Command
	AffectedRows  int
	LastInsertID  int
	StatusFlags   []GeneralPacketStatusFlag
	WarningsCount int
	// OKPacket is not completely implemented
}

type ERRPacket struct {
	Header MySQLHeader
	*Command
	ErrorCode      int
	SQLStateMarker string
	SQLState       string
	ErrorMessage   string
}

type EOFPacket struct {
	Header MySQLHeader
	*Command
	WarningsCount int
	StatusFlags   []GeneralPacketStatusFlag
}

/*
 * Command Phase
 */

type ComSleep struct {
	Header MySQLHeader
	*Command
}

type ComQuit struct {
	Header MySQLHeader
	*Command
}

type ComInitDb struct {
	Header MySQLHeader
	*Command
	SchemaName string
}

type ComQuery struct {
	Header MySQLHeader
	*Command
	Query string
}

type ComFieldList struct {
	Header MySQLHeader
	*Command
	Table         string
	FieldWildcard string
}

type ComCreateDb struct {
	Header MySQLHeader
	*Command
	SchemaName string
}

type ComDropDb struct {
	Header MySQLHeader
	*Command
	SchemaName string
}

type ComRefresh struct {
	Header MySQLHeader
	*Command
	SubCommand ComRefreshSubCommand
}

type ComShutdown struct {
	Header MySQLHeader
	*Command
	SubCommand ComShutdownSubCommand
}

type ComStatistics struct {
	Header MySQLHeader
	*Command
}

type ComProcessInfo struct {
	Header MySQLHeader
	*Command
}

type ComConnect struct {
	Header MySQLHeader
	*Command
}

type ComProcessKill struct {
	Header MySQLHeader
	*Command
	ConnectionID int
}

type ComDebug struct {
	Header MySQLHeader
	*Command
}

type ComPing struct {
	Header MySQLHeader
	*Command
}

type ComTime struct {
	Header MySQLHeader
	*Command
}

type ComDelayedInsert struct {
	Header MySQLHeader
	*Command
}

type ComChangeUser struct {
	Header MySQLHeader
	*Command
	User                 string
	AuthResponseLen      int
	AuthResponse         string
	SchemaName           string
	CharacterSet         CharacterSet
	AuthPluginName       string
	LengthOfAllKeyValues int
	Data                 map[string]string // Key Value pair
}

type ComBinlogDump struct {
	Header MySQLHeader
	*Command
	BinlogPosition int
	Flag           ComBinlogDumpFlag
	ServerID       int
	BinlogFileName string
}

type ComTableDump struct {
	Header MySQLHeader
	*Command
	DatabaseLen  int
	DatabaseName string
	TableLen     int
	TableName    string
}

type ComConnectOut struct {
	Header MySQLHeader
	*Command
}

type ComRegisterSlave struct {
	Header MySQLHeader
	*Command
	ServerID             int
	SlavesHostNameLength int
	SlavesHostName       string
	SlavesUserLength     int
	SlavesUser           string
	SlavesPasswordLength int
	SlavesPassword       string
	SlavesMySQLPort      int
	ReplicationRank      int
	MasterID             int
}

type ComSTMTPrepare struct {
	Header MySQLHeader
	*Command
	Query string
}

type ComSTMTExecute struct {
	Header MySQLHeader
	*Command
	STMTID               int
	Flags                ComSTMTExecuteFlags
	IterationCount       int
	NULLBitmap           string
	NewParamsBoundFlag   int
	TypeOfEachParameter  string
	ValueOfEachParameter string
}

type ComSTMTSendLongData struct {
	Header MySQLHeader
	*Command
	StatementID int
	ParamID     int
	Data        string
}

type ComSTMTClose struct {
	Header MySQLHeader
	*Command
	StatementID int
}

type ComSTMTReset struct {
	Header MySQLHeader
	*Command
	StatementID int
}

type ComSetOption struct {
	Header MySQLHeader
	*Command
	ComSetOptionOperation
}

type ComSTMTFetch struct {
	Header MySQLHeader
	*Command
	STMTID  int
	NumRows int
}

type ComDaemon struct {
	Header MySQLHeader
	*Command
}

type ComBinlogDumpGTID struct {
	Header MySQLHeader
	*Command
	Flags             ComBinlogDumpFlag
	ServerID          int
	BinlogFilenameLen int
	BinlogFilename    string
	BinlogPosition    int
	DataSize          int
	Data              string
}

type ComResetConnection struct {
	Header MySQLHeader
	*Command
}

type UnknownPacket struct {
	Header MySQLHeader
	*Command
}
