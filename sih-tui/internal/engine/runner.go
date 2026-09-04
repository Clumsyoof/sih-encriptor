package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// CoreBinary resolves the sih-core binary relative to this TUI binary at runtime.
// Layout: sih-tui/sih-tui  →  ../sih-core/target/debug/sih-core
func CoreBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot resolve executable path: %w", err)
	}
	// Resolve symlinks (e.g. go run temp paths)
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("cannot eval symlinks: %w", err)
	}
	tuiDir := filepath.Dir(exe)
	// From sih-tui/ go up one level to project root, then into sih-core
	coreBin := filepath.Join(tuiDir, "..", "sih-core", "target", "debug", "sih-core")
	coreBin = filepath.Clean(coreBin)
	if _, err := os.Stat(coreBin); err != nil {
		return "", fmt.Errorf("sih-core binary not found at %s — run 'cargo build' inside sih-core/", coreBin)
	}
	return coreBin, nil
}

// ProjectRoot returns the root of the sih project (parent of sih-tui/).
func ProjectRoot() string {
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	return filepath.Clean(filepath.Join(filepath.Dir(exe), ".."))
}

func run(args ...string) ([]byte, error) {
	core, err := CoreBinary()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(core, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("sih-core error: %s", string(ee.Stderr))
		}
		return nil, err
	}
	return out, nil
}

// ── Result types ──────────────────────────────────────────────────────────────

type ScanResult struct {
	ID           int    `json:"id"`
	Offset       uint64 `json:"offset"`
	FileType     string `json:"file_type"`
	Size         uint64 `json:"size"`
	Confidence   uint32 `json:"confidence"`
	IsFragmented bool   `json:"is_fragmented"`
	GapSize      uint64 `json:"gap_size"`
	Details      string `json:"details"`
}

type ErasureCert struct {
	OperationID   string  `json:"operation_id"`
	Timestamp     string  `json:"timestamp"`
	Target        string  `json:"target"`
	SizeBytes     uint64  `json:"target_size_bytes"`
	Method        string  `json:"method"`
	PreSHA256     string  `json:"pre_sha256"`
	PostSHA256    string  `json:"post_sha256"`
	PreEntropy    float64 `json:"pre_entropy"`
	PostEntropy   float64 `json:"post_entropy"`
	Passes        uint32  `json:"passes_completed"`
	Status        string  `json:"status"`
	HMACSignature string  `json:"hmac_signature"`
}

type EntropyResult struct {
	OverallEntropy float64   `json:"overall_entropy"`
	SectorCount    int       `json:"sector_count"`
	BlockSize      int       `json:"block_size"`
	Sectors        []float64 `json:"sectors"`
}

type BifragmentResult struct {
	Fragment1Offset        uint64 `json:"fragment1_offset"`
	Fragment1Size          uint64 `json:"fragment1_size"`
	GapOffset              uint64 `json:"gap_offset"`
	GapSize                uint64 `json:"gap_size"`
	Fragment2Offset        uint64 `json:"fragment2_offset"`
	Fragment2Size          uint64 `json:"fragment2_size"`
	TotalReconstructedSize uint64 `json:"total_reconstructed_size"`
	Confidence             uint32 `json:"confidence"`
	Status                 string `json:"status"`
	RecoveredFilePath      string `json:"recovered_file_path"`
	NaiveFilePath          string `json:"naive_file_path"`
}

// ── API ───────────────────────────────────────────────────────────────────────

func MakeDisk(outputPath string, sizeMB int) error {
	// Ensure parent dir exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	_, err := run("make-disk", "--output", outputPath, "--size-mb", fmt.Sprintf("%d", sizeMB))
	return err
}

func Scan(imagePath string) ([]ScanResult, error) {
	out, err := run("scan", "--image", imagePath, "--json")
	if err != nil {
		return nil, err
	}
	var results []ScanResult
	return results, json.Unmarshal(out, &results)
}

func Carve(imagePath, outputDir string) ([]ScanResult, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, err
	}
	out, err := run("carve", "--image", imagePath, "--output-dir", outputDir, "--json")
	if err != nil {
		return nil, err
	}
	var results []ScanResult
	return results, json.Unmarshal(out, &results)
}

func Erase(target, mode, certOut string, keepFile bool) (*ErasureCert, error) {
	args := []string{"erase", "--target", target, "--mode", mode, "--json"}
	if keepFile {
		args = append(args, "--keep-file")
	}
	if certOut != "" {
		args = append(args, "--cert-out", certOut)
	}
	out, err := run(args...)
	if err != nil {
		return nil, err
	}
	var cert ErasureCert
	return &cert, json.Unmarshal(out, &cert)
}

func Entropy(target string, blockSize int) (*EntropyResult, error) {
	args := []string{"entropy", "--target", target, "--json"}
	if blockSize > 0 {
		args = append(args, "--block-size", fmt.Sprintf("%d", blockSize))
	}
	out, err := run(args...)
	if err != nil {
		return nil, err
	}
	var result EntropyResult
	return &result, json.Unmarshal(out, &result)
}

func Bifragment(imagePath, outputDir string) (*BifragmentResult, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, err
	}
	out, err := run("bifragment", "--image", imagePath, "--output-dir", outputDir, "--json")
	if err != nil {
		return nil, err
	}
	s := string(out)
	if s == "null\n" || s == "null" || s == "" {
		return nil, nil
	}
	var result BifragmentResult
	return &result, json.Unmarshal(out, &result)
}
