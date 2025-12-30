package utils

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/cespare/xxhash/v2"
	"github.com/kalafut/imohash"
	"github.com/minio/highwayhash"
	"github.com/schollz/croc/v10/src/mnemonicode"
	log "github.com/schollz/logger"
	"github.com/schollz/progressbar/v3"
)

const NbPinNumbers = 4
const NbBytesWords = 4

// Get or create home directory
func GetConfigDir(requireValidPath bool) (homedir string, err error) {
	if envHomedir, isSet := os.LookupEnv("CROC_CONFIG_DIR"); isSet {
		homedir = envHomedir
	} else if xdgConfigHome, isSet := os.LookupEnv("XDG_CONFIG_HOME"); isSet {
		homedir = path.Join(xdgConfigHome, "croc")
	} else {
		homedir, err = os.UserHomeDir()
		if err != nil {
			if !requireValidPath {
				err = nil
				homedir = ""
			}
			return
		}
		homedir = path.Join(homedir, ".config", "croc")
	}

	if requireValidPath {
		if _, err = os.Stat(homedir); os.IsNotExist(err) {
			err = os.MkdirAll(homedir, 0o700)
		}
	}
	return
}

// Exists reports whether the named file or directory exists.
func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// GetInput returns the input with a given prompt
func GetInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "%s", prompt)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

// HashFile returns the hash of a file or, in case of a symlink, the
// SHA256 hash of its target. Takes an argument to specify the algorithm to use.
func HashFile(fname string, algorithm string, showProgress ...bool) (hash256 []byte, err error) {
	doShowProgress := false
	if len(showProgress) > 0 {
		doShowProgress = showProgress[0]
	}
	var fstats os.FileInfo
	fstats, err = os.Lstat(fname)
	if err != nil {
		return nil, err
	}
	if fstats.Mode()&os.ModeSymlink != 0 {
		var target string
		target, err = os.Readlink(fname)
		if err != nil {
			return nil, err
		}
		return []byte(SHA256(target)), nil
	}
	switch algorithm {
	case "imohash":
		return IMOHashFile(fname)
	case "md5":
		return MD5HashFile(fname, doShowProgress)
	case "xxhash":
		return XXHashFile(fname, doShowProgress)
	case "highway":
		return HighwayHashFile(fname, doShowProgress)
	}
	err = fmt.Errorf("unspecified algorithm")
	return
}

// HighwayHashFile returns highwayhash of a file
func HighwayHashFile(fname string, doShowProgress bool) (hashHighway []byte, err error) {
	f, err := os.Open(fname)
	if err != nil {
		return
	}
	defer f.Close()
	key, err := hex.DecodeString("1553c5383fb0b86578c3310da665b4f6e0521acf22eb58a99532ffed02a6b115")
	if err != nil {
		return
	}
	h, err := highwayhash.New(key)
	if err != nil {
		err = fmt.Errorf("could not create highwayhash: %s", err.Error())
		return
	}
	if doShowProgress {
		stat, _ := f.Stat()
		fnameShort := path.Base(fname)
		if len(fnameShort) > 20 {
			fnameShort = fnameShort[:20] + "..."
		}
		bar := progressbar.NewOptions64(stat.Size(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetDescription(fmt.Sprintf("Hashing %s", fnameShort)),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionFullWidth(),
		)
		if _, err = io.Copy(io.MultiWriter(h, bar), f); err != nil {
			return
		}
	} else {
		if _, err = io.Copy(h, f); err != nil {
			return
		}
	}

	hashHighway = h.Sum(nil)
	return
}

// MD5HashFile returns MD5 hash
func MD5HashFile(fname string, doShowProgress bool) (hash256 []byte, err error) {
	f, err := os.Open(fname)
	if err != nil {
		return
	}
	defer f.Close()

	h := md5.New()
	if doShowProgress {
		stat, _ := f.Stat()
		fnameShort := path.Base(fname)
		if len(fnameShort) > 20 {
			fnameShort = fnameShort[:20] + "..."
		}
		bar := progressbar.NewOptions64(stat.Size(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetDescription(fmt.Sprintf("Hashing %s", fnameShort)),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionFullWidth(),
		)
		if _, err = io.Copy(io.MultiWriter(h, bar), f); err != nil {
			return
		}
	} else {
		if _, err = io.Copy(h, f); err != nil {
			return
		}
	}

	hash256 = h.Sum(nil)
	return
}

var imofull = imohash.NewCustom(0, 0)
var imopartial = imohash.NewCustom(16*16*8*1024, 128*1024)

// IMOHashFile returns imohash
func IMOHashFile(fname string) (hash []byte, err error) {
	b, err := imopartial.SumFile(fname)
	hash = b[:]
	return
}

// IMOHashFileFull returns imohash of full file
func IMOHashFileFull(fname string) (hash []byte, err error) {
	b, err := imofull.SumFile(fname)
	hash = b[:]
	return
}

// XXHashFile returns the xxhash of a file
func XXHashFile(fname string, doShowProgress bool) (hash256 []byte, err error) {
	f, err := os.Open(fname)
	if err != nil {
		return
	}
	defer f.Close()

	h := xxhash.New()
	if doShowProgress {
		stat, _ := f.Stat()
		fnameShort := path.Base(fname)
		if len(fnameShort) > 20 {
			fnameShort = fnameShort[:20] + "..."
		}
		bar := progressbar.NewOptions64(stat.Size(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetDescription(fmt.Sprintf("Hashing %s", fnameShort)),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionFullWidth(),
		)
		if _, err = io.Copy(io.MultiWriter(h, bar), f); err != nil {
			return
		}
	} else {
		if _, err = io.Copy(h, f); err != nil {
			return
		}
	}

	hash256 = h.Sum(nil)
	return
}

// SHA256 returns sha256 sum
func SHA256(s string) string {
	sha := sha256.New()
	sha.Write([]byte(s))
	return hex.EncodeToString(sha.Sum(nil))
}

// PublicIP returns public ip address
func PublicIP() (ip string, err error) {
	// ask ipv4.icanhazip.com for the public ip
	// by making http request
	// if the request fails, return nothing
	resp, err := http.Get("http://ipv4.icanhazip.com")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// read the body of the response
	// and return the ip address
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	ip = strings.TrimSpace(buf.String())

	return
}

// LocalIP returns local ip address
func LocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Error(err)
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String()
}

// GenerateRandomPin returns a randomly generated pin with set length
func GenerateRandomPin() string {
	s := ""
	max := new(big.Int)
	max.SetInt64(9)
	for range NbPinNumbers {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		s += fmt.Sprintf("%d", v)
	}
	return s
}

// GetRandomName returns mnemonicoded random name
func GetRandomName() string {
	var result []string
	bs := make([]byte, NbBytesWords)
	rand.Read(bs)
	result = mnemonicode.EncodeWordList(result, bs)
	return GenerateRandomPin() + "-" + strings.Join(result, "-")
}

// ByteCountDecimal converts bytes to human readable byte string
func ByteCountDecimal(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

// MissingChunks returns the positions of missing chunks.
// If file doesn't exist, it returns an empty chunk list (all chunks).
// If the file size is not the same as requested, it returns an empty chunk list (all chunks).
func MissingChunks(fname string, fsize int64, chunkSize int) (chunkRanges []int64) {
	f, err := os.Open(fname)
	if err != nil {
		return
	}
	defer f.Close()

	fstat, err := os.Stat(fname)
	if err != nil || fstat.Size() != fsize {
		return
	}

	emptyBuffer := make([]byte, chunkSize)
	chunkNum := 0
	chunks := make([]int64, int64(math.Ceil(float64(fsize)/float64(chunkSize))))
	var currentLocation int64
	for {
		buffer := make([]byte, chunkSize)
		bytesread, err := f.Read(buffer)
		if err != nil {
			break
		}
		if bytes.Equal(buffer[:bytesread], emptyBuffer[:bytesread]) {
			chunks[chunkNum] = currentLocation
			chunkNum++
		}
		currentLocation += int64(bytesread)
	}
	if chunkNum == 0 {
		chunkRanges = []int64{}
	} else {
		chunks = chunks[:chunkNum]
		chunkRanges = []int64{int64(chunkSize), chunks[0]}
		curCount := 0
		for i, chunk := range chunks {
			if i == 0 {
				continue
			}
			curCount++
			if chunk-chunks[i-1] > int64(chunkSize) {
				chunkRanges = append(chunkRanges, int64(curCount))
				chunkRanges = append(chunkRanges, chunk)
				curCount = 0
			}
		}
		chunkRanges = append(chunkRanges, int64(curCount+1))
	}
	return
}

// ChunkRangesToChunks converts chunk ranges to list
func ChunkRangesToChunks(chunkRanges []int64) (chunks []int64) {
	if len(chunkRanges) == 0 {
		return
	}
	chunkSize := chunkRanges[0]
	chunks = []int64{}
	for i := 1; i < len(chunkRanges); i += 2 {
		for j := int64(0); j < (chunkRanges[i+1]); j++ {
			chunks = append(chunks, chunkRanges[i]+j*chunkSize)
		}
	}
	return
}

// GetLocalIPs returns all local ips
func GetLocalIPs() (ips []string, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	ips = []string{}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return
}

func RandomFileName() (fname string, err error) {
	f, err := os.CreateTemp(".", "croc-stdin-")
	if err != nil {
		return
	}
	fname = f.Name()
	_ = f.Close()
	return
}

func FindOpenPorts(host string, portNumStart, numPorts int) (openPorts []int) {
	openPorts = []int{}
	for port := portNumStart; port-portNumStart < 200; port++ {
		timeout := 100 * time.Millisecond
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
		if conn != nil {
			conn.Close()
		} else if err != nil {
			openPorts = append(openPorts, port)
		}
		if len(openPorts) >= numPorts {
			return
		}
	}
	return
}

// local ip determination
// https://stackoverflow.com/questions/41240761/check-if-ip-address-is-in-private-network-space
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func IsLocalIP(ipaddress string) bool {
	if strings.Contains(ipaddress, "127.0.0.1") {
		return true
	}
	host, _, _ := net.SplitHostPort(ipaddress)
	ip := net.ParseIP(host)
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func ZipDirectory(destination string, source string) (err error) {
	if _, err = os.Stat(destination); err == nil {
		log.Errorf("%s file already exists!\n", destination)
		return fmt.Errorf("file already exists: %s", destination)
	}

	// Check if source directory exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		log.Errorf("Source directory does not exist: %s", source)
		return fmt.Errorf("source directory does not exist: %s", source)
	}

	fmt.Fprintf(os.Stderr, "Zipping %s to %s\n", source, destination)
	file, err := os.Create(destination)
	if err != nil {
		log.Error(err)
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	// no compression because croc does its compression on the fly
	writer.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.NoCompression)
	})
	defer writer.Close()

	// Get base name for zip structure
	baseName := strings.TrimSuffix(filepath.Base(destination), ".zip")

	// First pass: add the root directory with its modification time
	rootInfo, err := os.Stat(source)
	if err == nil && rootInfo.IsDir() {
		header, err := zip.FileInfoHeader(rootInfo)
		if err != nil {
			log.Error(err)
		} else {
			header.Name = baseName + "/" // Trailing slash indicates directory
			header.Method = zip.Store
			header.Modified = rootInfo.ModTime()

			_, err = writer.CreateHeader(header)
			if err != nil {
				log.Error(err)
			} else {
				fmt.Fprintf(os.Stderr, "\r\033[2K")
				fmt.Fprintf(os.Stderr, "\rAdding %s", baseName+"/")
			}
		}
	}

	// Second pass: add all other directories and files
	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error(err)
			return nil
		}

		// Skip root directory (we already added it)
		if path == source {
			return nil
		}

		// Calculate relative path from source directory
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			log.Error(err)
			return nil
		}

		// Create zip path with base name structure
		zipPath := filepath.Join(baseName, relPath)
		zipPath = filepath.ToSlash(zipPath)

		if info.IsDir() {
			// Add directory entry to zip with original modification time
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				log.Error(err)
				return nil
			}
			header.Name = zipPath + "/" // Trailing slash indicates directory
			header.Method = zip.Store
			// Preserve the original modification time
			header.Modified = info.ModTime()

			_, err = writer.CreateHeader(header)
			if err != nil {
				log.Error(err)
				return nil
			}

			fmt.Fprintf(os.Stderr, "\r\033[2K")
			fmt.Fprintf(os.Stderr, "\rAdding %s", zipPath+"/")
			return nil
		}

		if info.Mode().IsRegular() {
			f1, err := os.Open(path)
			if err != nil {
				log.Error(err)
				return nil
			}
			defer f1.Close()

			// Create file header with modified time
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				log.Error(err)
				return nil
			}
			header.Name = zipPath
			header.Method = zip.Deflate

			w1, err := writer.CreateHeader(header)
			if err != nil {
				log.Error(err)
				return nil
			}

			if _, err := io.Copy(w1, f1); err != nil {
				log.Error(err)
				return nil
			}

			fmt.Fprintf(os.Stderr, "\r\033[2K")
			fmt.Fprintf(os.Stderr, "\rAdding %s", zipPath)
		}
		return nil
	})

	if err != nil {
		log.Error(err)
		return fmt.Errorf("error during directory walk: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\n")
	return nil
}

func UnzipDirectory(destination string, source string) error {
	archive, err := zip.OpenReader(source)
	if err != nil {
		log.Error(err)
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer archive.Close()

	// Store modification times for all files and directories
	modTimes := make(map[string]time.Time)

	// First pass: extract all files and directories, store modification times
	for _, f := range archive.File {
		filePath := filepath.Join(destination, f.Name)
		fmt.Fprintf(os.Stderr, "\r\033[2K")
		fmt.Fprintf(os.Stderr, "\rUnzipping file %s", filePath)

		// Issue #593 conceal path traversal vulnerability
		// make sure the filepath does not have ".."
		filePath = filepath.Clean(filePath)
		if strings.Contains(filePath, "..") {
			log.Errorf("Invalid file path %s\n", filePath)
			continue
		}

		// Store modification time for this entry (BOTH files and directories)
		modifiedTime := f.Modified
		if modifiedTime.IsZero() {
			modifiedTime = f.FileHeader.Modified
		}
		if !modifiedTime.IsZero() {
			modTimes[filePath] = modifiedTime
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				log.Error(err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			log.Error(err)
			continue
		}

		// check if file exists
		if _, err := os.Stat(filePath); err == nil {
			prompt := fmt.Sprintf("\nOverwrite '%s'? (y/N) ", filePath)
			choice := strings.ToLower(GetInput(prompt))
			if choice != "y" && choice != "yes" {
				fmt.Fprintf(os.Stderr, "Skipping '%s'\n", filePath)
				continue
			}
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			log.Error(err)
			continue
		}

		fileInArchive, err := f.Open()
		if err != nil {
			log.Error(err)
			dstFile.Close()
			continue
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			log.Error(err)
		}

		dstFile.Close()
		fileInArchive.Close()
	}

	// Second pass: restore modification times for ALL files and directories
	for path, modTime := range modTimes {
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			log.Errorf("Failed to set modification time for %s: %v", path, err)
		} else {
			fi, err := os.Lstat(path)
			if err != nil ||
				!modTime.UTC().Equal(fi.ModTime().UTC()) {
				log.Errorf("Failed to set modification time for %s: %v", path, err)
				fmt.Fprintf(os.Stderr, "Failed to set modification time %s %v: %v\n", path, modTime, err)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\n")
	return nil
}

// ValidFileName checks if a filename is valid
// by making sure it has no invisible characters
func ValidFileName(fname string) (err error) {
	// make sure it doesn't contain unicode or invisible characters
	for _, r := range fname {
		if !unicode.IsGraphic(r) {
			err = fmt.Errorf("non-graphical unicode: %x U+%d in '%x'", string(r), r, fname)
			return
		}
		if !unicode.IsPrint(r) {
			err = fmt.Errorf("non-printable unicode: %x U+%d in '%x'", string(r), r, fname)
			return
		}
	}
	// make sure basename does not include path separators
	_, basename := filepath.Split(fname)
	if strings.Contains(basename, string(os.PathSeparator)) {
		err = fmt.Errorf("basename cannot contain path separators: '%s'", basename)
		return
	}
	// make sure the filename is not an absolute path
	if filepath.IsAbs(fname) {
		err = fmt.Errorf("filename cannot be an absolute path: '%s'", fname)
		return
	}
	if !filepath.IsLocal(fname) {
		err = fmt.Errorf("filename must be a local path: '%s'", fname)
		return
	}
	return
}

const crocRemovalFile = "croc-marked-files.txt"

func MarkFileForRemoval(fname string) {
	// append the fname to the list of files to remove
	f, err := os.OpenFile(crocRemovalFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Debug(err)
		return
	}
	defer f.Close()
	_, err = f.WriteString(fname + "\n")
}

func RemoveMarkedFiles() (err error) {
	// read the file and remove all the files
	f, err := os.Open(crocRemovalFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fname := scanner.Text()
		err = os.Remove(fname)
		if err == nil {
			log.Tracef("Removed %s", fname)
		}
	}
	f.Close()
	os.Remove(crocRemovalFile)
	return
}

// RemoteConfigSource represents a remote configuration source
type RemoteConfigSource struct {
	BaseURL     string            `json:"base_url"`
	Endpoint    string            `json:"endpoint"`
	QueryParams map[string]string `json:"query_params"`
	Headers     map[string]string `json:"headers"`
	ProxyURL    string            `json:"proxy_url"`
}

// FetchContext maintains state across the fetch pipeline
type FetchContext struct {
	Source       *RemoteConfigSource
	ResolvedURL  string
	FinalURL     string
	HTTPClient   *http.Client
	Request      *http.Request
	ResponseData []byte
}

func FetchRemoteConfig(configData []byte) ([]byte, error) {
	var source RemoteConfigSource
	if err := json.Unmarshal(configData, &source); err != nil {
		return nil, fmt.Errorf("failed to parse config source: %w", err)
	}

	ctx := &FetchContext{
		Source: &source,
	}

	return ParseRemoteSource(ctx)
}

func ParseRemoteSource(ctx *FetchContext) ([]byte, error) {
	combinedURL := ctx.Source.BaseURL
	if !strings.HasSuffix(combinedURL, "/") && !strings.HasPrefix(ctx.Source.Endpoint, "/") {
		combinedURL += "/"
	}
	combinedURL += ctx.Source.Endpoint

	if len(ctx.Source.QueryParams) > 0 {
		params := make([]string, 0, len(ctx.Source.QueryParams))
		for key, value := range ctx.Source.QueryParams {
			params = append(params, fmt.Sprintf("%s=%s", key, value))
		}
		combinedURL += "?" + strings.Join(params, "&")
	}

	ctx.ResolvedURL = combinedURL
	return ValidateRemoteURL(ctx)
}

func ValidateRemoteURL(ctx *FetchContext) ([]byte, error) {
	if !strings.HasPrefix(ctx.ResolvedURL, "http://") && !strings.HasPrefix(ctx.ResolvedURL, "https://") {
		ctx.ResolvedURL = "https://" + ctx.ResolvedURL
	}

	blockedHosts := []string{"localhost", "127.0.0.1", "0.0.0.0"}
	urlLower := strings.ToLower(ctx.ResolvedURL)
	for _, blocked := range blockedHosts {
		if strings.Contains(urlLower, blocked) {
			return nil, fmt.Errorf("blocked host detected")
		}
	}

	ctx.FinalURL = ctx.ResolvedURL
	return BuildFetchRequest(ctx)
}

func BuildFetchRequest(ctx *FetchContext) ([]byte, error) {
	var err error
	ctx.Request, err = http.NewRequest("GET", ctx.FinalURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range ctx.Source.Headers {
		ctx.Request.Header.Set(key, value)
	}

	ctx.Request.Header.Set("User-Agent", "croc-remote-fetch/1.0")

	return PrepareHTTPClient(ctx)
}

func PrepareHTTPClient(ctx *FetchContext) ([]byte, error) {
	transport := &http.Transport{}

	if ctx.Source.ProxyURL != "" {
		proxyURL, err := url.Parse(ctx.Source.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	ctx.HTTPClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return ExecuteFetch(ctx)
}

func ExecuteFetch(ctx *FetchContext) ([]byte, error) {
	resp, err := ctx.HTTPClient.Do(ctx.Request)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	ctx.ResponseData = body
	return ProcessFetchResponse(ctx)
}

func ProcessFetchResponse(ctx *FetchContext) ([]byte, error) {
	if len(ctx.ResponseData) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	log.Debugf("fetched %d bytes from remote config", len(ctx.ResponseData))
	return ctx.ResponseData, nil
}

func NotifyWebhook(webhookURL string, eventType string, payload map[string]interface{}) error {
	return PrepareWebhookNotification(webhookURL, eventType, payload)
}

func PrepareWebhookNotification(webhookURL string, eventType string, payload map[string]interface{}) error {
	fullURL := ConstructWebhookURL(webhookURL, eventType)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return SendWebhookRequest(fullURL, payloadBytes)
}

func ConstructWebhookURL(baseURL string, eventType string) string {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return baseURL + "webhook/" + eventType
}

func SendWebhookRequest(webhookURL string, payload []byte) error {
	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error: %d", resp.StatusCode)
	}

	return nil
}

func ResolveAndFetch(hostname string, port int, path string) ([]byte, error) {
	resolvedIP, err := ResolveHostname(hostname)
	if err != nil {
		return nil, err
	}

	return FetchFromResolvedHost(resolvedIP, port, path)
}

func ResolveHostname(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for hostname")
	}
	return ips[0].String(), nil
}

func FetchFromResolvedHost(ip string, port int, path string) ([]byte, error) {
	targetURL := fmt.Sprintf("http://%s:%d%s", ip, port, path)

	resp, err := http.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
