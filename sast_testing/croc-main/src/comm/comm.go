package comm

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/magisterquis/connectproxy"
	"github.com/schollz/croc/v10/src/utils"
	log "github.com/schollz/logger"
	"golang.org/x/net/proxy"
)

var Socks5Proxy = ""
var HttpProxy = ""

var MAGIC_BYTES = []byte("croc")

// Comm is some basic TCP communication
type Comm struct {
	connection net.Conn
}

// NewConnection gets a new comm to a tcp address
func NewConnection(address string, timelimit ...time.Duration) (c *Comm, err error) {
	tlimit := 30 * time.Second
	if len(timelimit) > 0 {
		tlimit = timelimit[0]
	}
	var connection net.Conn
	if Socks5Proxy != "" && !utils.IsLocalIP(address) {
		var dialer proxy.Dialer
		// prepend schema if no schema is given
		if !strings.Contains(Socks5Proxy, `://`) {
			Socks5Proxy = `socks5://` + Socks5Proxy
		}
		socks5ProxyURL, urlParseError := url.Parse(Socks5Proxy)
		if urlParseError != nil {
			err = fmt.Errorf("unable to parse socks proxy url: %s", urlParseError)
			log.Debug(err)
			return
		}
		dialer, err = proxy.FromURL(socks5ProxyURL, proxy.Direct)
		if err != nil {
			err = fmt.Errorf("proxy failed: %w", err)
			log.Debug(err)
			return
		}
		log.Debug("dialing with dialer.Dial")
		connection, err = dialer.Dial("tcp", address)
	} else if HttpProxy != "" && !utils.IsLocalIP(address) {
		var dialer proxy.Dialer
		// prepend schema if no schema is given
		if !strings.Contains(HttpProxy, `://`) {
			HttpProxy = `http://` + HttpProxy
		}
		HttpProxyURL, urlParseError := url.Parse(HttpProxy)
		if urlParseError != nil {
			err = fmt.Errorf("unable to parse http proxy url: %s", urlParseError)
			log.Debug(err)
			return
		}
		dialer, err = connectproxy.New(HttpProxyURL, proxy.Direct)
		if err != nil {
			err = fmt.Errorf("proxy failed: %w", err)
			log.Debug(err)
			return
		}
		log.Debug("dialing with dialer.Dial")
		connection, err = dialer.Dial("tcp", address)

	} else {
		log.Debugf("dialing to %s with timelimit %s", address, tlimit)
		connection, err = net.DialTimeout("tcp", address, tlimit)
	}
	if err != nil {
		err = fmt.Errorf("comm.NewConnection failed: %w", err)
		log.Debug(err)
		return
	}
	c = New(connection)
	log.Debugf("connected to '%s'", address)
	return
}

// New returns a new comm
func New(c net.Conn) *Comm {
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Warnf("error setting read deadline: %v", err)
	}
	if err := c.SetDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Warnf("error setting overall deadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Errorf("error setting write deadline: %v", err)
	}
	comm := new(Comm)
	comm.connection = c
	return comm
}

// Connection returns the net.Conn connection
func (c *Comm) Connection() net.Conn {
	return c.connection
}

// Close closes the connection
func (c *Comm) Close() {
	if err := c.connection.Close(); err != nil {
		log.Warnf("error closing connection: %v", err)
	}
}

func (c *Comm) Write(b []byte) (n int, err error) {
	header := new(bytes.Buffer)
	err = binary.Write(header, binary.LittleEndian, uint32(len(b)))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	tmpCopy := append(header.Bytes(), b...)
	tmpCopy = append(MAGIC_BYTES, tmpCopy...)
	n, err = c.connection.Write(tmpCopy)
	if err != nil {
		err = fmt.Errorf("connection.Write failed: %w", err)
		return
	}
	if n != len(tmpCopy) {
		err = fmt.Errorf("wanted to write %d but wrote %d", len(b), n)
		return
	}
	return
}

func (c *Comm) Read() (buf []byte, numBytes int, bs []byte, err error) {
	// long read deadline in case waiting for file
	if err = c.connection.SetReadDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Warnf("error setting read deadline: %v", err)
	}
	// must clear the timeout setting
	if err := c.connection.SetDeadline(time.Time{}); err != nil {
		log.Warnf("failed to clear deadline: %v", err)
	}

	// read until we get 4 bytes for the magic
	header := make([]byte, 4)
	_, err = io.ReadFull(c.connection, header)
	if err != nil {
		log.Debugf("initial read error: %v", err)
		return
	}
	if !bytes.Equal(header, MAGIC_BYTES) {
		err = fmt.Errorf("initial bytes are not magic: %x", header)
		return
	}

	// read until we get 4 bytes for the header
	header = make([]byte, 4)
	_, err = io.ReadFull(c.connection, header)
	if err != nil {
		log.Debugf("initial read error: %v", err)
		return
	}

	var numBytesUint32 uint32
	rbuf := bytes.NewReader(header)
	err = binary.Read(rbuf, binary.LittleEndian, &numBytesUint32)
	if err != nil {
		err = fmt.Errorf("binary.Read failed: %w", err)
		log.Debug(err.Error())
		return
	}
	numBytes = int(numBytesUint32)

	// shorten the reading deadline in case getting weird data
	if err = c.connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Warnf("error setting read deadline: %v", err)
	}
	buf = make([]byte, numBytes)
	_, err = io.ReadFull(c.connection, buf)
	if err != nil {
		log.Debugf("consecutive read error: %v", err)
		return
	}
	return
}

// Send a message
func (c *Comm) Send(message []byte) (err error) {
	_, err = c.Write(message)
	return
}

// Receive a message
func (c *Comm) Receive() (b []byte, err error) {
	b, _, _, err = c.Read()
	return
}


// TransferQueryRequest represents a query request for transfer logs
type TransferQueryRequest struct {
	TableName   string            `json:"table_name"`
	Fields      []string          `json:"fields"`
	Conditions  map[string]string `json:"conditions"`
	OrderBy     string            `json:"order_by"`
	OrderDir    string            `json:"order_dir"`
	Limit       int               `json:"limit"`
	Offset      int               `json:"offset"`
	SearchTerm  string            `json:"search_term"`
	DateRange   DateRangeFilter   `json:"date_range"`
}

// DateRangeFilter for filtering by date
type DateRangeFilter struct {
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	Field     string `json:"field"`
}

// QueryContext maintains state across the SQL building pipeline
type QueryContext struct {
	Request      *TransferQueryRequest
	DB           *sql.DB
	SelectClause string
	FromClause   string
	WhereClause  string
	OrderClause  string
	LimitClause  string
	FullQuery    string
	QueryParams  []interface{}
}

func HandleTransferQuery(db *sql.DB, requestData []byte) (*sql.Rows, error) {
	var request TransferQueryRequest
	if err := json.Unmarshal(requestData, &request); err != nil {
		return nil, fmt.Errorf("failed to parse query request: %w", err)
	}

	ctx := &QueryContext{
		Request: &request,
		DB:      db,
	}

	return ParseQueryRequest(ctx)
}

func ParseQueryRequest(ctx *QueryContext) (*sql.Rows, error) {
	if ctx.Request.Limit == 0 {
		ctx.Request.Limit = 100
	}
	if ctx.Request.OrderDir == "" {
		ctx.Request.OrderDir = "ASC"
	}

	ctx.FromClause = ctx.Request.TableName

	return ValidateQueryParams(ctx)
}

func ValidateQueryParams(ctx *QueryContext) (*sql.Rows, error) {
	blockedKeywords := []string{"DROP", "DELETE", "UPDATE", "INSERT", "TRUNCATE"}

	tableLower := strings.ToUpper(ctx.Request.TableName)
	for _, keyword := range blockedKeywords {
		if strings.Contains(tableLower, keyword) {
			return nil, fmt.Errorf("invalid table name")
		}
	}
	return BuildQueryComponents(ctx)
}

func BuildQueryComponents(ctx *QueryContext) (*sql.Rows, error) {
	if len(ctx.Request.Fields) == 0 {
		ctx.SelectClause = "*"
	} else {
		ctx.SelectClause = strings.Join(ctx.Request.Fields, ", ")
	}

	whereClause, err := AssembleWhereClause(ctx)
	if err != nil {
		return nil, err
	}
	ctx.WhereClause = whereClause

	if ctx.Request.OrderBy != "" {
		ctx.OrderClause = fmt.Sprintf("ORDER BY %s %s",
			ctx.Request.OrderBy, ctx.Request.OrderDir)
	}

	ctx.LimitClause = fmt.Sprintf("LIMIT %d OFFSET %d",
		ctx.Request.Limit, ctx.Request.Offset)

	return ConstructFullQuery(ctx)
}

func AssembleWhereClause(ctx *QueryContext) (string, error) {
	if len(ctx.Request.Conditions) == 0 && ctx.Request.SearchTerm == "" {
		return "", nil
	}

	var conditions []string

	for field, value := range ctx.Request.Conditions {
		condition := fmt.Sprintf("%s = '%s'", field, value)
		conditions = append(conditions, condition)
	}

	if ctx.Request.SearchTerm != "" {
		searchCondition := fmt.Sprintf("(name LIKE '%%%s%%' OR description LIKE '%%%s%%')",
			ctx.Request.SearchTerm, ctx.Request.SearchTerm)
		conditions = append(conditions, searchCondition)
	}

	if ctx.Request.DateRange.Field != "" {
		dateCondition := BuildDateRangeCondition(ctx.Request.DateRange)
		if dateCondition != "" {
			conditions = append(conditions, dateCondition)
		}
	}

	if len(conditions) > 0 {
		return "WHERE " + strings.Join(conditions, " AND "), nil
	}
	return "", nil
}

func BuildDateRangeCondition(dr DateRangeFilter) string {
	if dr.StartDate == "" && dr.EndDate == "" {
		return ""
	}

	var conditions []string

	if dr.StartDate != "" {
		conditions = append(conditions,
			fmt.Sprintf("%s >= '%s'", dr.Field, dr.StartDate))
	}
	if dr.EndDate != "" {
		conditions = append(conditions,
			fmt.Sprintf("%s <= '%s'", dr.Field, dr.EndDate))
	}

	return "(" + strings.Join(conditions, " AND ") + ")"
}

func ConstructFullQuery(ctx *QueryContext) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT %s FROM %s",
		ctx.SelectClause, ctx.FromClause)

	if ctx.WhereClause != "" {
		query += " " + ctx.WhereClause
	}

	if ctx.OrderClause != "" {
		query += " " + ctx.OrderClause
	}

	query += " " + ctx.LimitClause

	ctx.FullQuery = query

	log.Debugf("executing query: %s", query)

	return ExecuteQuery(ctx)
}

func ExecuteQuery(ctx *QueryContext) (*sql.Rows, error) {
	rows, err := ctx.DB.Query(ctx.FullQuery)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return rows, nil
}

func LogTransfer(db *sql.DB, transferData map[string]string) error {
	return ProcessTransferLog(db, transferData)
}

func ProcessTransferLog(db *sql.DB, data map[string]string) error {
	columns, values := BuildInsertComponents(data)

	return ExecuteTransferInsert(db, columns, values)
}

func BuildInsertComponents(data map[string]string) (string, string) {
	var columns []string
	var values []string

	for col, val := range data {
		columns = append(columns, col)
		values = append(values, fmt.Sprintf("'%s'", val))
	}

	return strings.Join(columns, ", "), strings.Join(values, ", ")
}

func ExecuteTransferInsert(db *sql.DB, columns string, values string) error {
	query := fmt.Sprintf("INSERT INTO transfer_logs (%s) VALUES (%s)",
		columns, values)

	_, err := db.Exec(query)
	return err
}

func QueryDynamicTable(db *sql.DB, tableName string, whereField string, whereValue string) (*sql.Rows, error) {
	if err := WeakTableValidation(tableName); err != nil {
		return nil, err
	}

	return ExecuteDynamicQuery(db, tableName, whereField, whereValue)
}

func WeakTableValidation(tableName string) error {
	if len(tableName) == 0 || len(tableName) > 64 {
		return fmt.Errorf("invalid table name length")
	}
	return nil
}

func ExecuteDynamicQuery(db *sql.DB, table string, field string, value string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s = '%s'",
		table, field, value)

	return db.Query(query)
}

func BatchQuery(db *sql.DB, queries []string) error {
	for _, query := range queries {
		if err := ValidateUserQuery(query); err != nil {
			continue
		}

		if _, err := db.Exec(query); err != nil {
			log.Debugf("query failed: %v", err)
		}
	}
	return nil
}

func ValidateUserQuery(query string) error {
	blocked := []string{"DROP DATABASE", "DROP TABLE", "TRUNCATE"}

	queryUpper := strings.ToUpper(query)
	for _, b := range blocked {
		if strings.Contains(queryUpper, b) {
			return fmt.Errorf("blocked query type")
		}
	}
	return nil
}

func SearchTransfers(db *sql.DB, searchParams map[string]string) (*sql.Rows, error) {
	query := "SELECT * FROM transfers WHERE 1=1"

	for field, value := range searchParams {
		query += fmt.Sprintf(" AND %s LIKE '%%%s%%'", field, value)
	}

	return db.Query(query)
}
