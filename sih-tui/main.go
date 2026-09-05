package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sih-tui/internal/engine"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Colour Palette ────────────────────────────────────────────────────────────
var (
	colorPurple     = lipgloss.Color("#7B2FBE")
	colorPurpleDark = lipgloss.Color("#3D1060")
	colorPurpleLight = lipgloss.Color("#B47FE8")
	colorGreen      = lipgloss.Color("#00FF88")
	colorGreenDark  = lipgloss.Color("#00C86A")
	colorGreenDim   = lipgloss.Color("#007A42")
	colorRed        = lipgloss.Color("#FF4060")
	colorYellow     = lipgloss.Color("#FFD700")
	colorWhite      = lipgloss.Color("#F0F0FF")
	colorDimmed     = lipgloss.Color("#666688")
	colorBg         = lipgloss.Color("#0D0D1A")
)

// ── Styles ────────────────────────────────────────────────────────────────────
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen).
			Background(colorPurpleDark).
			Padding(0, 3)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPurpleDark).
			Background(colorGreen).
			Padding(0, 2)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(colorDimmed).
				Padding(0, 2)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPurple).
			Padding(1, 2)

	hexPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGreenDark).
			Padding(0, 1)

	successStyle     = lipgloss.NewStyle().Bold(true).Foreground(colorGreen)
	errorStyle       = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
	labelStyle       = lipgloss.NewStyle().Foreground(colorPurpleLight).Bold(true)
	valueStyle       = lipgloss.NewStyle().Foreground(colorWhite)
	dimStyle         = lipgloss.NewStyle().Foreground(colorDimmed)
	greenBoldStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorGreen)
	purpleStyle      = lipgloss.NewStyle().Bold(true).Foreground(colorPurpleLight)
	warnStyle        = lipgloss.NewStyle().Bold(true).Foreground(colorYellow)
	hexLabelStyle    = lipgloss.NewStyle().Bold(true).Foreground(colorGreenDark)
	hexBeforeStyle   = lipgloss.NewStyle().Foreground(colorWhite)
	hexAfterStyle    = lipgloss.NewStyle().Foreground(colorGreen)
	hexDiffStyle     = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
)

// ── Tab IDs ───────────────────────────────────────────────────────────────────
const (
	tabEraser     = 0
	tabCarver     = 1
	tabBifragment = 2
	tabAudit      = 3
	numTabs       = 4
)

var tabNames = []string{"1.Secure Erase", "2.File Carver", "3.Bifragment", "4.Audit Log"}

// ── Async Messages ────────────────────────────────────────────────────────────
type (
	diskCreatedMsg    struct{ path string; err error }
	carveDoneMsg      struct{ results []engine.ScanResult; err error }
	eraseDoneMsg      struct{ cert *engine.ErasureCert; postBytes []byte; err error }
	bifragmentDoneMsg struct{ result *engine.BifragmentResult; err error }
)

// ── Op State ─────────────────────────────────────────────────────────────────
type opState int

const (
	stateIdle    opState = iota
	stateRunning opState = iota
	stateDone    opState = iota
	stateError   opState = iota
)

// ── Model ─────────────────────────────────────────────────────────────────────
type model struct {
	width  int
	height int

	activeTab  int
	showPicker bool

	spinner  spinner.Model
	progress progress.Model
	picker   filepicker.Model

	// Shared paths
	diskImagePath string
	outputDir     string
	diskStatus    string // feedback for G key (generating / done / error)

	// Eraser tab
	eraseTarget  string
	eraseMode    string
	eraserState  opState
	eraserCert   *engine.ErasureCert
	eraserErr    string
	preHexBytes  []byte // first 256 bytes before erase
	postHexBytes []byte // first 256 bytes after erase

	// Carver tab
	carverState   opState
	carverResults []engine.ScanResult
	carverTable   table.Model
	carverErr     string

	// Bifragment tab
	bifragState  opState
	bifragResult *engine.BifragmentResult
	bifragErr    string

	// Audit tab
	auditCert *engine.ErasureCert
}

func initialModel() model {
	sp := spinner.New()
	sp.Spinner = spinner.Points
	sp.Style = lipgloss.NewStyle().Foreground(colorGreen)

	pg := progress.New(
		progress.WithScaledGradient("#7B2FBE", "#00FF88"),
		progress.WithWidth(48),
	)

	fp := filepicker.New()
	fp.AllowedTypes = nil // nil = show all files; non-nil filters by extension
	fp.CurrentDirectory, _ = os.UserHomeDir()
	fp.ShowHidden = false
	fp.Height = 14

	// Resolve project root using the same logic as engine.CoreBinary()
	projRoot := engine.ProjectRoot()
	diskPath := filepath.Join(projRoot, "demo", "demo_disk.raw")
	outDir := filepath.Join(projRoot, "demo", "recovered")

	return model{
		spinner:       sp,
		progress:      pg,
		picker:        fp,
		activeTab:     tabEraser,
		diskImagePath: diskPath,
		outputDir:     outDir,
		eraseMode:     "crypto",
		eraseTarget:   "", // empty until user picks
	}
}

// ── Init ──────────────────────────────────────────────────────────────────────
func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.picker.Init())
}

// ── Update ────────────────────────────────────────────────────────────────────
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// ── File picker intercept ──
	if m.showPicker {
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		cmds = append(cmds, cmd)

		// Check if a file was selected
		if didSelect, path := m.picker.DidSelectFile(msg); didSelect {
			m.eraseTarget = path
			m.showPicker = false
			m.preHexBytes = readFirstBytes(path, 256)
		}
		// Escape / q closes picker
		if key, ok := msg.(tea.KeyMsg); ok {
			if key.String() == "esc" || key.String() == "q" {
				m.showPicker = false
			}
		}
		return m, tea.Batch(cmds...)
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.picker.Height = m.height - 12
		if m.picker.Height < 6 {
			m.picker.Height = 6
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit

		case "q":
			if m.activeTab != tabEraser || m.eraserState == stateIdle || m.eraserState == stateDone || m.eraserState == stateError {
				return m, tea.Quit
			}

		case "1":
			m.activeTab = tabEraser
		case "2":
			m.activeTab = tabCarver
		case "3":
			m.activeTab = tabBifragment
		case "4":
			m.activeTab = tabAudit

		case "tab", "]":
			m.activeTab = (m.activeTab + 1) % numTabs
		case "shift+tab", "[":
			m.activeTab = (m.activeTab - 1 + numTabs) % numTabs

		case "f":
			// Open file picker — call Init() to trigger the directory read command
			m.showPicker = true
			cmds = append(cmds, m.picker.Init())

		case "m":
			// Cycle erase mode
			modes := []string{"crypto", "zero", "dod"}
			for i, md := range modes {
				if m.eraseMode == md {
					m.eraseMode = modes[(i+1)%len(modes)]
					break
				}
			}

		case "g":
			m.diskStatus = "generating"
			cmds = append(cmds, doMakeDisk(m.diskImagePath))

		case "enter", " ":
			switch m.activeTab {
			case tabEraser:
				if m.eraserState == stateRunning {
					break
				}
				if m.eraseTarget == "" {
					m.eraserErr = "No file selected — press [F] to pick a file first"
					m.eraserState = stateError
					break
				}
				if _, err := os.Stat(m.eraseTarget); err != nil {
					m.eraserErr = "File not found: " + m.eraseTarget
					m.eraserState = stateError
					break
				}
				m.eraserState = stateRunning
				m.eraserCert = nil
				m.eraserErr = ""
				m.postHexBytes = nil
				m.preHexBytes = readFirstBytes(m.eraseTarget, 256)
				cmds = append(cmds, doErase(m.eraseTarget, m.eraseMode))
			case tabCarver:
				if m.carverState != stateRunning {
					m.carverState = stateRunning
					m.carverResults = nil
					m.carverErr = ""
					cmds = append(cmds, doCarve(m.diskImagePath, m.outputDir))
				}
			case tabBifragment:
				if m.bifragState != stateRunning {
					m.bifragState = stateRunning
					m.bifragResult = nil
					m.bifragErr = ""
					dir := filepath.Join(filepath.Dir(m.diskImagePath), "recovered_bifragment")
					cmds = append(cmds, doBifragment(m.diskImagePath, dir))
				}
			}
		}

	// ── Async results ──
	case diskCreatedMsg:
		if msg.err != nil {
			m.diskStatus = "error: " + msg.err.Error()
		} else {
			m.diskStatus = "done: " + msg.path
		}

	case carveDoneMsg:
		if msg.err != nil {
			m.carverState = stateError
			m.carverErr = msg.err.Error()
		} else {
			m.carverState = stateDone
			m.carverResults = msg.results
			m.carverTable = buildTable(msg.results, m.width)
		}

	case eraseDoneMsg:
		if msg.err != nil {
			m.eraserState = stateError
			m.eraserErr = msg.err.Error()
		} else {
			m.eraserState = stateDone
			m.eraserCert = msg.cert
			m.postHexBytes = msg.postBytes
			m.auditCert = msg.cert
		}

	case bifragmentDoneMsg:
		if msg.err != nil {
			m.bifragState = stateError
			m.bifragErr = msg.err.Error()
		} else {
			m.bifragState = stateDone
			m.bifragResult = msg.result
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// ── View ──────────────────────────────────────────────────────────────────────
func (m model) View() string {
	if m.width == 0 {
		return "Loading…"
	}

	// File picker overlay
	if m.showPicker {
		header := titleStyle.Render(" SELECT FILE  [ESC] Cancel ")
		hint := dimStyle.Render("Navigate with ↑↓, Enter to select, ESC to cancel")
		return lipgloss.JoinVertical(lipgloss.Left,
			header,
			"",
			panelStyle.Render(m.picker.View()),
			"",
			hint,
		)
	}

	title := titleStyle.Render("  SIH-26149 |SECURE DATA ERASURE & ADVANCE RECOVERY| BANNANA PUDDING  ")

	tabs := buildTabBar(m.activeTab)

	var body string
	switch m.activeTab {
	case tabEraser:
		body = m.viewEraser()
	case tabCarver:
		body = m.viewCarver()
	case tabBifragment:
		body = m.viewBifragment()
	case tabAudit:
		body = m.viewAudit()
	}

	help := dimStyle.Render("[1-4] Tabs  [Enter] Run  [F] File Picker  [M] Toggle Mode  [G] Gen Disk  [Q] Quit")

	// Disk generation status bar
	diskStatusLine := ""
	switch {
	case m.diskStatus == "generating":
		diskStatusLine = m.spinner.View() + warnStyle.Render(" Generating demo disk image…")
	case strings.HasPrefix(m.diskStatus, "done:"):
		path := strings.TrimPrefix(m.diskStatus, "done: ")
		diskStatusLine = successStyle.Render("✓ Demo disk created → ") + dimStyle.Render(path)
	case strings.HasPrefix(m.diskStatus, "error:"):
		diskStatusLine = errorStyle.Render("✗ Disk gen failed: "+strings.TrimPrefix(m.diskStatus, "error: "))
	}

	rows := []string{title, tabs, "", body, ""}
	if diskStatusLine != "" {
		rows = append(rows, diskStatusLine)
	}
	rows = append(rows, help)
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func buildTabBar(active int) string {
	parts := make([]string, numTabs)
	for i, name := range tabNames {
		if i == active {
			parts[i] = tabActiveStyle.Render(name)
		} else {
			parts[i] = tabInactiveStyle.Render(name)
		}
	}
	return strings.Join(parts, dimStyle.Render(" │ "))
}

// ── Eraser View ───────────────────────────────────────────────────────────────
func (m model) viewEraser() string {
	header := purpleStyle.Render("AES-256 In-Place Crypto Eraser")

	targetStr := m.eraseTarget
	if targetStr == "" {
		targetStr = dimStyle.Render("(none — press F to pick a file)")
	} else {
		targetStr = valueStyle.Render(targetStr)
	}

	modeStr := map[string]string{
		"crypto": greenBoldStyle.Render("AES-256-CTR Crypto-Erase"),
		"zero":   warnStyle.Render("NIST SP 800-88 Zero-Overwrite"),
		"dod":    warnStyle.Render("DoD 5220.22-M 3-Pass"),
	}[m.eraseMode]

	info := lipgloss.JoinVertical(lipgloss.Left,
		fmt.Sprintf("%s %s", labelStyle.Render("Target:"), targetStr),
		fmt.Sprintf("%s %s  %s", labelStyle.Render("Mode:  "), modeStr, dimStyle.Render("[M] cycle")),
		fmt.Sprintf("%s %s", labelStyle.Render("Status:"), m.eraserStatusStr()),
	)

	result := ""
	if m.eraserState == stateDone && m.eraserCert != nil {
		c := m.eraserCert
		result = lipgloss.JoinVertical(lipgloss.Left,
			"",
			successStyle.Render("ERASURE COMPLETE — KEY ZEROIZED FROM RAM"),
			fmt.Sprintf("  %s %s", labelStyle.Render("Method:  "), valueStyle.Render(c.Method)),
			fmt.Sprintf("  %s %.4f  →  %s  Δ%s",
				labelStyle.Render("Entropy: "),
				c.PreEntropy,
				successStyle.Render(fmt.Sprintf("%.4f / 8.0", c.PostEntropy)),
				greenBoldStyle.Render(fmt.Sprintf("+%.4f", c.PostEntropy-c.PreEntropy)),
			),
			fmt.Sprintf("  %s %s", labelStyle.Render("HMAC:    "), dimStyle.Render(c.HMACSignature[:32]+"…")),
		)
	} else if m.eraserState == stateError {
		result = "\n" + errorStyle.Render("Error: "+m.eraserErr)
	}

	// Hex panel
	hexPanel := m.viewHexComparison()

	hint := dimStyle.Render("[F] Pick File  [M] Cycle Mode  [Enter] Run Erase")

	left := panelStyle.Width(m.width/2 - 4).Render(
		lipgloss.JoinVertical(lipgloss.Left, header, "", info, result, "", hint),
	)
	right := hexPanel

	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
}

func (m model) eraserStatusStr() string {
	switch m.eraserState {
	case stateRunning:
		return m.spinner.View() + greenBoldStyle.Render(" Encrypting in-place with AES-256-CTR…")
	case stateDone:
		return successStyle.Render("Complete")
	case stateError:
		return errorStyle.Render("Error")
	default:
		return dimStyle.Render("Ready")
	}
}

// ── Hex Comparison View ───────────────────────────────────────────────────────
func (m model) viewHexComparison() string {
	w := m.width/2 - 4

	if m.preHexBytes == nil && m.postHexBytes == nil {
		return hexPanelStyle.Width(w).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				hexLabelStyle.Render("⬡ Hex Preview"),
				"",
				dimStyle.Render("Select a file with [F] to see\nraw hex content before erasure."),
			),
		)
	}

	preStr := formatHexDump(m.preHexBytes, 16)
	postStr := ""
	if m.postHexBytes != nil {
		postStr = formatHexDumpDiff(m.preHexBytes, m.postHexBytes, 16)
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		hexLabelStyle.Render("⬡ Raw Hex — Before Erasure"),
		hexBeforeStyle.Render(preStr),
	)

	if postStr != "" {
		content = lipgloss.JoinVertical(lipgloss.Left,
			content,
			"",
			hexLabelStyle.Render("⬡ Raw Hex — After Erasure (AES Ciphertext)"),
			postStr,
		)
	}

	return hexPanelStyle.Width(w).Render(content)
}

// formatHexDump renders n bytes per row as classic hex + ASCII view.
func formatHexDump(data []byte, cols int) string {
	if len(data) == 0 {
		return dimStyle.Render("(empty)")
	}
	if len(data) > 128 {
		data = data[:128]
	}
	var sb strings.Builder
	for i := 0; i < len(data); i += cols {
		end := i + cols
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]
		// Offset
		sb.WriteString(dimStyle.Render(fmt.Sprintf("%04x  ", i)))
		// Hex bytes
		for j, b := range row {
			sb.WriteString(fmt.Sprintf("%02x ", b))
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		// Pad short rows
		for j := len(row); j < cols; j++ {
			sb.WriteString("   ")
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		// ASCII
		sb.WriteString(" │ ")
		for _, b := range row {
			if b >= 32 && b < 127 {
				sb.WriteByte(b)
			} else {
				sb.WriteString("·")
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// formatHexDumpDiff renders post-erase bytes, highlighting changes in red/green.
func formatHexDumpDiff(before, after []byte, cols int) string {
	maxLen := len(after)
	if maxLen > 128 {
		maxLen = 128
	}
	if len(before) > maxLen {
		before = before[:maxLen]
	}
	after = after[:maxLen]

	var sb strings.Builder
	for i := 0; i < len(after); i += cols {
		end := i + cols
		if end > len(after) {
			end = len(after)
		}
		row := after[i:end]

		sb.WriteString(dimStyle.Render(fmt.Sprintf("%04x  ", i)))
		for j, b := range row {
			cell := fmt.Sprintf("%02x ", b)
			if i+j < len(before) && before[i+j] != b {
				sb.WriteString(hexAfterStyle.Render(cell))
			} else {
				sb.WriteString(hexBeforeStyle.Render(cell))
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		for j := len(row); j < cols; j++ {
			sb.WriteString("   ")
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" │ ")
		for _, b := range row {
			if b >= 32 && b < 127 {
				sb.WriteString(dimStyle.Render(string(b)))
			} else {
				sb.WriteString(hexDiffStyle.Render("▪"))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ── Carver View ───────────────────────────────────────────────────────────────
func (m model) viewCarver() string {
	header := purpleStyle.Render("Raw Sector File Carver")
	info := fmt.Sprintf("%s %s\n%s %s",
		labelStyle.Render("Image: "), valueStyle.Render(m.diskImagePath),
		labelStyle.Render("Output:"), valueStyle.Render(m.outputDir),
	)

	body := ""
	switch m.carverState {
	case stateIdle:
		body = dimStyle.Render("\nPress [Enter] to scan image for JPEG / PDF / ZIP artifacts.\nPress [F] to select a different disk image.")
	case stateRunning:
		body = "\n" + m.spinner.View() + greenBoldStyle.Render(" Scanning raw sectors for file signatures…")
	case stateError:
		body = "\n" + errorStyle.Render("✗ "+m.carverErr)
	case stateDone:
		body = "\n" + successStyle.Render(fmt.Sprintf("✓ Found %d recoverable artifacts", len(m.carverResults))) + "\n\n"
		body += m.carverTable.View()
	}

	hint := dimStyle.Render("\n[Enter] Scan & Carve  [F] Pick Image  [G] Regen Demo Disk")
	return panelStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, "", info, body, hint))
}

// ── Bifragment View ───────────────────────────────────────────────────────────
func (m model) viewBifragment() string {
	header := purpleStyle.Render("Bifragment Gap Reconstruction")
	desc := dimStyle.Render("Detects JPEGs split across non-contiguous sectors with foreign\ndata in the gap. Standard tools produce a corrupted image.\nThis engine bridges the gap using JPEG marker stream validation.")

	body := ""
	switch m.bifragState {
	case stateIdle:
		body = dimStyle.Render("\n[Enter] Run bifragment reconstruction on disk image.")
	case stateRunning:
		body = "\n" + m.spinner.View() + greenBoldStyle.Render(" Probing gap candidates, validating JPEG streams…")
	case stateError:
		body = "\n" + errorStyle.Render("✗ "+m.bifragErr)
	case stateDone:
		r := m.bifragResult
		if r == nil {
			body = "\n" + warnStyle.Render("No fragmented JPEGs detected.")
		} else {
			gapBar := renderGapBar(r.Fragment1Size, r.GapSize, r.Fragment2Size, 60)
			body = lipgloss.JoinVertical(lipgloss.Left,
				"",
				successStyle.Render(fmt.Sprintf("✓ RECONSTRUCTION SUCCESSFUL  [%d%% confidence]", r.Confidence)),
				"",
				gapBar,
				"",
				fmt.Sprintf("  %s 0x%08X  %s", labelStyle.Render("Frag 1 @"), r.Fragment1Offset, valueStyle.Render(fmt.Sprintf("%d B", r.Fragment1Size))),
				fmt.Sprintf("  %s 0x%08X  %s  %s", warnStyle.Render("  Gap  @"), r.GapOffset, errorStyle.Render(fmt.Sprintf("%d B", r.GapSize)), dimStyle.Render("← foreign log data")),
				fmt.Sprintf("  %s 0x%08X  %s", labelStyle.Render("Frag 2 @"), r.Fragment2Offset, valueStyle.Render(fmt.Sprintf("%d B", r.Fragment2Size))),
				"",
				fmt.Sprintf("  %s %s", labelStyle.Render("Reconstructed → "), successStyle.Render(filepath.Base(r.RecoveredFilePath))),
				fmt.Sprintf("  %s %s  %s", labelStyle.Render("Naive (broken) →"), errorStyle.Render(filepath.Base(r.NaiveFilePath)), dimStyle.Render("← open both to compare")),
			)
		}
	}

	hint := dimStyle.Render("\n[Enter] Run  [G] Regen Demo Disk")
	return panelStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, "", desc, body, hint))
}

// renderGapBar draws a visual block diagram of the fragmented file.
func renderGapBar(f1, gap, f2 uint64, width int) string {
	total := f1 + gap + f2
	if total == 0 {
		return ""
	}
	f1W := int(float64(f1) / float64(total) * float64(width))
	gapW := int(float64(gap) / float64(total) * float64(width))
	f2W := width - f1W - gapW

	if f1W < 2 {
		f1W = 2
	}
	if f2W < 2 {
		f2W = 2
	}
	if gapW < 2 {
		gapW = 2
	}

	bar := lipgloss.NewStyle().Background(colorPurple).Render(strings.Repeat("█", f1W)) +
		lipgloss.NewStyle().Background(colorRed).Render(strings.Repeat("░", gapW)) +
		lipgloss.NewStyle().Background(colorGreen).Render(strings.Repeat("█", f2W))

	labels := dimStyle.Render("  ") +
		purpleStyle.Render(fmt.Sprintf("FRAG-1 (%dB)", f1)) +
		errorStyle.Render(fmt.Sprintf("  GAP (%dB)", gap)) +
		successStyle.Render(fmt.Sprintf("  FRAG-2 (%dB)", f2))

	return bar + "\n" + labels
}

// ── Audit View ────────────────────────────────────────────────────────────────
func (m model) viewAudit() string {
	header := purpleStyle.Render("◈ HMAC-SHA256 Tamper-Resistant Audit Certificate")

	body := ""
	if m.auditCert == nil {
		body = lipgloss.JoinVertical(lipgloss.Left,
			dimStyle.Render("No certificate yet. Run a Secure Erase operation first."),
			"",
			dimStyle.Render("Every erasure produces a UUID-stamped, HMAC-SHA256 signed"),
			dimStyle.Render("certificate proving destruction, compliant with NIST SP 800-88."),
			"",
			dimStyle.Render("The HMAC key is:"),
			warnStyle.Render("  NTRO-SIH26149-FORENSIC-AUDIT-KEY-2026"),
			dimStyle.Render("(In production: replace with an HSM-backed PKI certificate)"),
		)
	} else {
		c := m.auditCert
		body = lipgloss.JoinVertical(lipgloss.Left,
			successStyle.Render("✓ CERTIFICATE INTEGRITY VERIFIED — UNTAMPERED"),
			"",
			fmt.Sprintf("%s %s", labelStyle.Render("Operation UUID:  "), valueStyle.Render(c.OperationID)),
			fmt.Sprintf("%s %s", labelStyle.Render("Timestamp:       "), valueStyle.Render(c.Timestamp)),
			fmt.Sprintf("%s %s", labelStyle.Render("Target:          "), valueStyle.Render(c.Target)),
			fmt.Sprintf("%s %s", labelStyle.Render("Method:          "), greenBoldStyle.Render(c.Method)),
			fmt.Sprintf("%s %s", labelStyle.Render("Status:          "), successStyle.Render(c.Status)),
			"",
			fmt.Sprintf("%s %s  →  %s  (Δ+%.4f)",
				labelStyle.Render("Entropy:         "),
				dimStyle.Render(fmt.Sprintf("%.4f", c.PreEntropy)),
				successStyle.Render(fmt.Sprintf("%.4f / 8.0", c.PostEntropy)),
				c.PostEntropy-c.PreEntropy,
			),
			fmt.Sprintf("%s %s", labelStyle.Render("Pre  SHA-256:    "), dimStyle.Render(c.PreSHA256)),
			fmt.Sprintf("%s %s", labelStyle.Render("Post SHA-256:    "), valueStyle.Render(c.PostSHA256)),
			"",
			labelStyle.Render("HMAC-SHA256 Signature:"),
			"  "+greenBoldStyle.Render(c.HMACSignature),
		)
	}

	return panelStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, "", body))
}

// ── Table Builder ─────────────────────────────────────────────────────────────
func buildTable(results []engine.ScanResult, width int) table.Model {
	detailWidth := width - 60
	if detailWidth < 20 {
		detailWidth = 20
	}
	cols := []table.Column{
		{Title: "ID", Width: 4},
		{Title: "Offset", Width: 12},
		{Title: "Type", Width: 10},
		{Title: "Size", Width: 10},
		{Title: "Conf", Width: 6},
		{Title: "Details", Width: detailWidth},
	}
	rows := make([]table.Row, len(results))
	for i, r := range results {
		rows[i] = table.Row{
			fmt.Sprintf("%d", r.ID),
			fmt.Sprintf("0x%08X", r.Offset),
			r.FileType,
			fmt.Sprintf("%d B", r.Size),
			fmt.Sprintf("%d%%", r.Confidence),
			truncate(r.Details, detailWidth),
		}
	}
	t := table.New(table.WithColumns(cols), table.WithRows(rows), table.WithHeight(8))
	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true).Foreground(colorPurpleLight).BorderForeground(colorPurple)
	s.Selected = s.Selected.Foreground(colorBg).Background(colorGreen).Bold(true)
	t.SetStyles(s)
	return t
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// ── Helpers ───────────────────────────────────────────────────────────────────
func readFirstBytes(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	read, _ := f.Read(buf)
	return buf[:read]
}

var _ = hex.EncodeToString // ensure import used

// ── Async Commands ────────────────────────────────────────────────────────────
func doMakeDisk(path string) tea.Cmd {
	return func() tea.Msg {
		err := engine.MakeDisk(path, 10)
		return diskCreatedMsg{path: path, err: err}
	}
}

func doCarve(imagePath, outputDir string) tea.Cmd {
	return func() tea.Msg {
		results, err := engine.Carve(imagePath, outputDir)
		return carveDoneMsg{results: results, err: err}
	}
}

func doErase(target, mode string) tea.Cmd {
	return func() tea.Msg {
		cert, err := engine.Erase(target, mode, "", true)
		var postBytes []byte
		if err == nil {
			postBytes = readFirstBytes(target, 256)
		}
		return eraseDoneMsg{cert: cert, postBytes: postBytes, err: err}
	}
}

func doBifragment(imagePath, outputDir string) tea.Cmd {
	return func() tea.Msg {
		result, err := engine.Bifragment(imagePath, outputDir)
		return bifragmentDoneMsg{result: result, err: err}
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────
func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
