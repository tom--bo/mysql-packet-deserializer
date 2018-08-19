package mysqlpacket

type CommandType string

const (
	// Connection Phase Packet
	HANDSHAKE_V10                       = "HANDSHAKE_V10"
	HANDSHAKE_RESPONSE41                = "HANDSHAKE_RESPONSE41"
	SSL_REQUEST                         = "SSL_REQUEST"
	AUTH_SWITCH_REQUEST                 = "AUTH_SWITCH_REQUEST"
	OLD_AUTH_SWITCH_REQUEST             = "OLD_AUTH_SWITCH_REQUEST"
	AUTH_SWITCH_RESPONSE                = "AUTH_SWITCH_RESPONSE"
	AUTH_MORE_DATA                      = "AUTH_MORE_DATA"
	// General Response Packet
	OK_PACKET                           = "OK_PACKET"
	ERR_PACKET                          = "ERR_PACKET"
	EOF_PACKET                          = "EOF_PACKET"
	// Command Phase Packet
	COM_SLEEP               CommandType = "COM_SLEEP"
	COM_QUIT                            = "COM_QUIT"
	COM_INIT_DB                         = "COM_INIT_DB"
	COM_QUERY                           = "COM_QUERY"
	COM_FIELD_LIST                      = "COM_FIELD_LIST"
	COM_CREATE_DB                       = "COM_CREATE_DB"
	COM_DROP_DB                         = "COM_DROP_DB"
	COM_REFRESH                         = "COM_REFRESH"
	COM_SHUTDOWN                        = "COM_SHUTDOWN"
	COM_STATISTICS                      = "COM_STATISTICS"
	COM_PROCESS_INFO                    = "COM_PROCESS_INFO"
	COM_CONNECT                         = "COM_CONNECT"
	COM_PROCESS_KILL                    = "COM_PROCESS_KILL"
	COM_DEBUG                           = "COM_DEBUG"
	COM_PING                            = "COM_PING"
	COM_TIME                            = "COM_TIME"
	COM_DELAYED_INSERT                  = "COM_DELAYED_INSERT"
	COM_CHANGE_USER                     = "COM_CHANGE_USER"
	COM_BINLOG_DUMP                     = "COM_BINLOG_DUMP"
	COM_TABLE_DUMP                      = "COM_TABLE_DUMP"
	COM_CONNECT_OUT                     = "COM_CONNECT_OUT"
	COM_REGISTER_SLAVE                  = "COM_REGISTER_SLAVE"
	COM_STMT_PREPARE                    = "COM_STMT_PREPARE"
	COM_STMT_EXECUTE                    = "COM_STMT_EXECUTE"
	COM_STMT_SEND_LONG_DATA             = "COM_STMT_SEND_LONG_DATA"
	COM_STMT_CLOSE                      = "COM_STMT_CLOSE"
	COM_STMT_RESET                      = "COM_STMT_RESET"
	COM_SET_OPTION                      = "COM_SET_OPTION"
	COM_STMT_FETCH                      = "COM_STMT_FETCH"
	COM_DAEMON                          = "COM_DAEMON"
	COM_BINLOG_DUMP_GTID                = "COM_BINLOG_DUMP_GTID"
	COM_RESET_CONNECTION                = "COM_RESET_CONNECTION"
	// Unknown or Not Supported Packet
	UNKNOWN_PACKET                      = "UNKNOWN_PACKET"
)

type CharacterSet string

const (
	UNKNOWN_CHARACTER_SET CharacterSet   = "UNKNOWN_CHARACTER_SET"
)

type CapacityFlag string

const (
	UNKNOWN_CAPACITY_FLAG CapacityFlag   = "UNKNOWN_CAPACITY_FLAG"
)

/*
	capacityFlag := map[string]string{
		string([]byte{0x00, 0x00, 0x00, 0x01}): "CLIENT_LONG_PASSWORD",
		string([]byte{0x00, 0x00, 0x00, 0x02}): "CLIENT_FOUND_ROWS",
		string([]byte{0x00, 0x00, 0x00, 0x04}): "CLIENT_LONG_FLAG",
		string([]byte{0x00, 0x00, 0x00, 0x08}): "CLIENT_CONNECT_WITH_DB",
		string([]byte{0x00, 0x00, 0x00, 0x10}): "CLIENT_NO_SCHEMA",
		string([]byte{0x00, 0x00, 0x00, 0x20}): "CLIENT_COMPRESS",
		string([]byte{0x00, 0x00, 0x00, 0x40}): "CLIENT_ODBC",
		string([]byte{0x00, 0x00, 0x00, 0x80}): "CLIENT_LOCAL_FILES",
		string([]byte{0x00, 0x00, 0x01, 0x00}): "CLIENT_IGNORE_SPACE",
		string([]byte{0x00, 0x00, 0x02, 0x00}): "CLIENT_41",
		string([]byte{0x00, 0x00, 0x04, 0x00}): "CLIENT_INTERACTIVE",
		string([]byte{0x00, 0x00, 0x08, 0x00}): "CLIENT_SSL",
		string([]byte{0x00, 0x00, 0x10, 0x00}): "CLIENT_IGNORE_SIGPIPE",
		string([]byte{0x00, 0x00, 0x20, 0x00}): "CLIENT_TRANSACTIONS",
		string([]byte{0x00, 0x00, 0x40, 0x00}): "CLIENT_RESERVED",
		string([]byte{0x00, 0x00, 0x80, 0x00}): "CLIENT_SECURE_CONNECTION",
		string([]byte{0x00, 0x01, 0x00, 0x00}): "CLIENT_MULTI_STATEMENTS",
		string([]byte{0x00, 0x02, 0x00, 0x00}): "CLIENT_MULTI_RESULTS",
		string([]byte{0x00, 0x04, 0x00, 0x00}): "CLIENT_PS_MULTI_RESULTS",
		string([]byte{0x00, 0x08, 0x00, 0x00}): "CLIENT_PLUGIN_AUTH",
		string([]byte{0x00, 0x10, 0x00, 0x00}): "CLIENT_CONNECT_ATTRS",
		string([]byte{0x00, 0x20, 0x00, 0x00}): "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
		string([]byte{0x00, 0x40, 0x00, 0x00}): "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
		string([]byte{0x00, 0x80, 0x00, 0x00}): "CLIENT_SESSION_TRACK",
		string([]byte{0x01, 0x00, 0x00, 0x00}): "CLIENT_DEPRECATE_EOF"}
*/

type ComRefreshSubCommand string

const (
	REFRESH_GRANT ComRefreshSubCommand = "REFRESH_GRANT"
	REFRESH_LOG = "REFRESH_LOG"
	REFRESH_TABLES = "REFRESH_TABLES"
	REFRESH_HOSTS = "REFRESH_HOSTS"
	REFRESH_STATUS = "REFRESH_STATUS"
	REFRESH_THREADS = "REFRESH_THREADS"
	REFRESH_SLAVE = "REFRESH_SLAVE"
	REFRESH_MASTER = "REFRESH_MASTER"
	COM_REFRESH_SUBCOMMAND_UNKNOWN = "COM_REFRESH_SUBCOMMAND_UNKNOWN"
)

type ComShutdownSubCommand string

const (
	SHUTDOWN_DEFAULT ComShutdownSubCommand = "SHUTDOWN_DEFAULT"
	SHUTDOWN_WAIT_CONNECTIONS = "SHUTDOWN_WAIT_CONNECTIONS"
	SHUTDOWN_WAIT_TRANSACTIONS = "SHUTDOWN_WAIT_TRANSACTIONS"
	SHUTDOWN_WAIT_UPDATES = "SHUTDOWN_WAIT_UPDATES"
	SHUTDOWN_WAIT_ALL_BUFFERS = "SHUTDOWN_WAIT_ALL_BUFFERS"
	SHUTDOWN_WAIT_CRITICAL_BUFFERS = "SHUTDOWN_WAIT_CRITICAL_BUFFERS"
	KILL_QUERY = "KILL_QUERY"
	KILL_CONNECTION = "KILL_CONNECTION"
	COM_SHUTDOWN_SUBCOMMAND_UNKNOWN = "COM_SHUTDOWN_SUBCOMMAND_UNKNOWN"
)

type ComSetOptionOperation string

const (
	MYSQL_OPTION_MULTI_STATEMENTS_ON ComSetOptionOperation = "MYSQL_OPTION_MULTI_STATEMENTS_ON"
	MYSQL_OPTION_MULTI_STATEMENTS_OFF = "MYSQL_OPTION_MULTI_STATEMENTS_OFF"
	COM_SET_OPTION_OPERATION_UNKNOWN = "COM_SET_OPTION_OPERATION_UNKNOWN"
)

type ComBinlogDumpFlag string
// This type is used as ComBinlogDumpGTIDFlags also

const (
	BINLOG_DUMP_NON_BLOCK ComBinlogDumpFlag = "BINLOG_DUMP_NON_BLOCK"
	BINLOG_THROUGH_POSITION = "BINLOG_THROUGH_POSITION"
	BINLOG_THROUGH_GTID = "BINLOG_THROUGH_GTID"
	COM_BINLOG_DUMP_FLAG_UNKONWN = "COM_BINLOG_DUMP_FLAG_UNKONWN"
)

type ComSTMTExecuteFlags string

const (
	CURSOR_TYPE_NO_CURSOR ComSTMTExecuteFlags = "CURSOR_TYPE_NO_CURSOR"
	CURSOR_TYPE_READ_ONLY = "CURSOR_TYPE_READ_ONLY"
	CURSOR_TYPE_FOR_UPDATE = "CURSOR_TYPE_FOR_UPDATE"
	CURSOR_TYPE_SCROLLABLE = "CURSOR_TYPE_SCROLLABLE"
	COM_STMT_EXECUTE_FLAG_UNKONWN = "COM_STMT_EXECUTE_FLAG_UNKONWN"
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
	ServerVersion string
	ConnectionID int
	AuthPluginDataPart1 string
	CapabilityFlagsLower2Bytes []byte
	// Not implemented completely now ...
}

type HandshakeResponse41 struct {
	Header MySQLHeader
	*Command
	CapacityFlag []CapacityFlag
	MaxPacketSize int
	CharacterSet CharacterSet
}

type SSLRequest struct {
	Header MySQLHeader
	*Command
	CapacityFlag []CapacityFlag
	MaxPacketSize int
	CharacterSet CharacterSet
}

type AuthSwitchRequest struct {
	Header MySQLHeader
	*Command
	PluginName string
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
}

type ERRPacket struct {
	Header MySQLHeader
	*Command
}

type EOFPacket struct {
	Header MySQLHeader
	*Command
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
	Table string
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
	User string
	AuthResponseLen int
	AuthResponse string
	SchemaName string
	CharacterSet CharacterSet
	AuthPluginName string
	LengthOfAllKeyValues int
	Data map[string]string // Key Value pair
}

type ComBinlogDump struct {
	Header MySQLHeader
	*Command
	BinlogPosition int
	Flag ComBinlogDumpFlag
	ServerID int
	BinlogFileName string
}

type ComTableDump struct {
	Header MySQLHeader
	*Command
	DatabaseLen int
	DatabaseName string
	TableLen int
	TableName string
}

type ComConnectOut struct {
	Header MySQLHeader
	*Command
}

type ComRegisterSlave struct {
	Header MySQLHeader
	*Command
	ServerID int
	SlavesHostNameLength int
	SlavesHostName string
	SlavesUserLength int
	SlavesUser string
	SlavesPasswordLength int
	SlavesPassword string
	SlavesMySQLPort int
	ReplicationRank int
	MasterID int
}

type ComSTMTPrepare struct {
	Header MySQLHeader
	*Command
	Query string
}

type ComSTMTExecute struct {
	Header MySQLHeader
	*Command
	STMTID int
	Flags ComSTMTExecuteFlags
	IterationCount int
	NULLBitmap string
	NewParamsBoundFlag int
	TypeOfEachParameter string
	ValueOfEachParameter string
}

type ComSTMTSendLongData struct {
	Header MySQLHeader
	*Command
	StatementID int
	ParamID int
	Data string
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
	STMTID int
	NumRows int
}

type ComDaemon struct {
	Header MySQLHeader
	*Command
}

type ComBinlogDumpGTID struct {
	Header MySQLHeader
	*Command
	Flags ComBinlogDumpFlag
	ServerID int
	BinlogFilenameLen int
	BinlogFilename string
	BinlogPosition int
	DataSize int
	Data string
}

type ComResetConnection struct {
	Header MySQLHeader
	*Command
}

type UnknownPacket struct {
	Header MySQLHeader
	*Command
}
