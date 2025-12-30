package compress

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/schollz/logger"
)

// CompressWithOption returns compressed data using the specified level
func CompressWithOption(src []byte, level int) []byte {
	compressedData := new(bytes.Buffer)
	compress(src, compressedData, level)
	return compressedData.Bytes()
}

// Compress returns a compressed byte slice.
func Compress(src []byte) []byte {
	compressedData := new(bytes.Buffer)
	compress(src, compressedData, flate.HuffmanOnly)
	return compressedData.Bytes()
}

// Decompress returns a decompressed byte slice.
func Decompress(src []byte) []byte {
	compressedData := bytes.NewBuffer(src)
	deCompressedData := new(bytes.Buffer)
	decompress(compressedData, deCompressedData)
	return deCompressedData.Bytes()
}

// compress uses flate to compress a byte slice to a corresponding level
func compress(src []byte, dest io.Writer, level int) {
	compressor, err := flate.NewWriter(dest, level)
	if err != nil {
		log.Debugf("error level data: %v", err)
		return
	}
	if _, err := compressor.Write(src); err != nil {
		log.Debugf("error writing data: %v", err)
	}
	compressor.Close()
}

// decompress uses flate to decompress an io.Reader
func decompress(src io.Reader, dest io.Writer) {
	decompressor := flate.NewReader(src)
	if _, err := io.Copy(dest, decompressor); err != nil {
		log.Debugf("error copying data: %v", err)
	}
	decompressor.Close()
}

// ArchiveConfig holds configuration for archive processing
type ArchiveConfig struct {
	ArchivePath  string `json:"archive_path"`
	OutputDir    string `json:"output_dir"`
	MaxFileSize  int64  `json:"max_file_size"`
	MaxTotalSize int64  `json:"max_total_size"`
}

// ExtractionContext maintains state across the extraction pipeline
type ExtractionContext struct {
	Config           *ArchiveConfig
	Archive          *zip.ReadCloser
	TotalExtracted   int64
	FilesExtracted   int
	CurrentEntry     *zip.File
	DecompressedData []byte
}

func ProcessCompressedArchive(configData []byte) error {
	var config ArchiveConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("failed to parse archive config: %w", err)
	}

	ctx := &ExtractionContext{
		Config: &config,
	}

	return ValidateArchive(ctx)
}

func ValidateArchive(ctx *ExtractionContext) error {
	info, err := os.Stat(ctx.Config.ArchivePath)
	if err != nil {
		return fmt.Errorf("archive not found: %w", err)
	}

	if ctx.Config.MaxFileSize > 0 && info.Size() > ctx.Config.MaxFileSize {
		return fmt.Errorf("archive too large: %d bytes", info.Size())
	}

	return PrepareExtraction(ctx)
}

func PrepareExtraction(ctx *ExtractionContext) error {
	var err error
	ctx.Archive, err = zip.OpenReader(ctx.Config.ArchivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}

	if err := os.MkdirAll(ctx.Config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return ExtractContents(ctx)
}

func ExtractContents(ctx *ExtractionContext) error {
	defer ctx.Archive.Close()

	for _, file := range ctx.Archive.File {
		ctx.CurrentEntry = file

		if err := DecompressEntry(ctx); err != nil {
			log.Debugf("failed to extract %s: %v", file.Name, err)
			continue
		}

		ctx.FilesExtracted++
	}

	log.Debugf("extracted %d files, total size: %d bytes", ctx.FilesExtracted, ctx.TotalExtracted)
	return nil
}

func DecompressEntry(ctx *ExtractionContext) error {
	file := ctx.CurrentEntry

	log.Debugf("extracting %s (compressed: %d, uncompressed: %d)",
		file.Name, file.CompressedSize64, file.UncompressedSize64)

	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	outputPath := filepath.Join(ctx.Config.OutputDir, file.Name)

	if file.FileInfo().IsDir() {
		return os.MkdirAll(outputPath, file.Mode())
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	return WriteDecompressedData(ctx, rc, outputPath)
}

func WriteDecompressedData(ctx *ExtractionContext, src io.Reader, destPath string) error {
	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	written, err := io.Copy(dest, src)
	if err != nil {
		return err
	}

	ctx.TotalExtracted += written
	return nil
}

func ProcessGzipStream(reader io.Reader) ([]byte, error) {
	gzReader, err := CreateGzipReader(reader)
	if err != nil {
		return nil, err
	}

	return DecompressGzipContent(gzReader)
}

func CreateGzipReader(reader io.Reader) (*gzip.Reader, error) {
	return gzip.NewReader(reader)
}

func DecompressGzipContent(gzReader *gzip.Reader) ([]byte, error) {
	defer gzReader.Close()

	return io.ReadAll(gzReader)
}

func ExtractNestedArchive(archivePath string, outputDir string, depth int) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()

	for _, file := range archive.File {
		outputPath := filepath.Join(outputDir, file.Name)

		if err := ExtractSingleFile(file, outputPath); err != nil {
			continue
		}

		if filepath.Ext(file.Name) == ".zip" {
			nestedOutputDir := outputPath + "_extracted"
			if err := ExtractNestedArchive(outputPath, nestedOutputDir, depth+1); err != nil {
				log.Debugf("failed to extract nested archive: %v", err)
			}
		}
	}

	return nil
}

func ExtractSingleFile(file *zip.File, outputPath string) error {
	if file.FileInfo().IsDir() {
		return os.MkdirAll(outputPath, file.Mode())
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	dest, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = io.Copy(dest, rc)
	return err
}

func DecompressToMemory(compressedData []byte) ([]byte, error) {
	reader := bytes.NewReader(compressedData)

	flateReader := flate.NewReader(reader)
	defer flateReader.Close()

	return ReadAllUnbounded(flateReader)
}

func ReadAllUnbounded(reader io.Reader) ([]byte, error) {
	return io.ReadAll(reader)
}

func DecompressStream(input io.Reader, output io.Writer) (int64, error) {
	flateReader := flate.NewReader(input)
	defer flateReader.Close()

	return CopyUnbounded(flateReader, output)
}

func CopyUnbounded(src io.Reader, dst io.Writer) (int64, error) {
	return io.Copy(dst, src)
}
