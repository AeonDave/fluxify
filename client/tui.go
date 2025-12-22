package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

type ifaceChoice struct {
	Name       string
	IP         string
	HasGateway bool
}

type tuiRunner struct{}

func (tuiRunner) Run(name string, args ...string) error {
	return common.RunPrivileged(name, args...)
}

func (tuiRunner) Output(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

func (tuiRunner) OutputSafe(name string, args ...string) ([]byte, error) {
	return common.RunPrivilegedOutput(name, args...)
}

// runTUI launches the interactive UI for bonding/load-balance configuration.
func runTUI(initial clientConfig, autoStart bool) {
	app := tview.NewApplication()
	app.EnableMouse(true)

	state := newTUIState(initial)
	autoStartOnce := sync.Once{}

	// Widgets
	modeDrop := tview.NewDropDown().SetLabel("Mode ")
	modeDrop.SetOptions([]string{modeBonding, modeLoadBalance}, nil)
	if initial.Mode == modeLoadBalance {
		modeDrop.SetCurrentOption(1)
	} else {
		// ensure a default selection to avoid -1 index
		modeDrop.SetCurrentOption(0)
	}

	serverField := tview.NewInputField().SetLabel("Server ").SetText(state.server)

	ifaceList := tview.NewList().ShowSecondaryText(true)
	ifaceList.SetBorder(true).SetTitle("Interfaces (select with mouse/Enter)")
	ifaceList.SetSelectedBackgroundColor(tcell.ColorWhite)
	ifaceList.SetSelectedTextColor(tcell.ColorBlack)

	info := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true).SetWrap(true)
	info.SetBorder(true).SetTitle("Info & Usage")
	log.SetOutput(&tuiLogWriter{app: app, view: info})

	status := tview.NewTextView().SetDynamicColors(true).SetText("Select mode, server, and at least 2 interfaces")
	status.SetBorder(true).SetTitle("Status")

	styleBtn := func(b *tview.Button) {
		b.SetBorder(false)
		b.SetBackgroundColor(tcell.ColorDefault)
		b.SetLabelColor(tcell.ColorWhite)
		b.SetLabelColorActivated(tcell.ColorYellow)
	}

	startBtn := tview.NewButton("[ Start ]")
	styleBtn(startBtn)
	stopBtn := tview.NewButton("[ Stop ]")
	styleBtn(stopBtn)
	stopBtn.SetDisabled(true)
	refreshBtn := tview.NewButton("[ Refresh IFs ]")
	styleBtn(refreshBtn)
	quitBtn := tview.NewButton("[ Quit ]")
	styleBtn(quitBtn)

	// Layout: top row = Config (left 1/2) + Actions (right 1/2)
	configBox := tview.NewFlex().SetDirection(tview.FlexRow)
	configBox.SetBorder(true).SetTitle("Config")
	configBox.AddItem(modeDrop, 1, 0, false)
	configBox.AddItem(serverField, 1, 0, false)

	actionsBox := tview.NewFlex().SetDirection(tview.FlexRow)
	actionsBox.SetBorder(true).SetTitle("Actions")
	actionsBox.AddItem(tview.NewBox(), 0, 1, false) // top spacer
	actionsBox.AddItem(startBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 1, 0, false)
	actionsBox.AddItem(stopBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 1, 0, false)
	actionsBox.AddItem(refreshBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 1, 0, false)
	actionsBox.AddItem(quitBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 0, 1, false) // bottom spacer

	topRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	topRow.AddItem(configBox, 0, 1, false)
	topRow.AddItem(actionsBox, 0, 1, false)

	// Main layout
	form := tview.NewFlex().SetDirection(tview.FlexRow)
	form.AddItem(topRow, 9, 0, false)
	form.AddItem(ifaceList, 0, 1, true)
	form.AddItem(info, 10, 0, false)
	form.AddItem(status, 3, 0, false)

	app.SetRoot(form, true).SetFocus(ifaceList)

	// Populate interfaces
	var refreshIfaces func()
	var redrawList func()
	var updateButtons func()
	var updateStatus func()
	var persistConfig func()
	var start func()

	serverFieldDisabled := false
	suppressServerChange := false
	var starting bool // prevent multiple concurrent starts and preserve info panel

	persistConfig = func() {
		if starting || state.running != nil {
			return
		}
		cfg := state.buildConfig()
		saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Client: cfg.Client, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
	}

	redrawList = func() {
		ifaceList.Clear()
		for _, c := range state.choices {
			checked := state.selected[c.Name]
			label := c.Name
			if c.IP != "" {
				label += " (" + c.IP + ")"
			}
			mark := "[ ] "
			if checked {
				mark = "[x] "
			}
			if !c.HasGateway {
				state.selected[c.Name] = false
				label = "[red]" + label + " (no gateway)"
				mark = "[ ] "
			}
			choice := c
			ifaceList.AddItem(mark+label, "", 0, func() {
				// Block toggles while running
				if starting || state.running != nil {
					status.SetText("[yellow]Running: stop before changing interfaces")
					return
				}
				if !choice.HasGateway {
					status.SetText("[red]Interface has no gateway; pick another")
					return
				}
				state.toggle(choice.Name)
				persistConfig()
				redrawList()
				updateButtons()
			})
		}
	}

	refreshIfaces = func() {
		// Do not allow modifying interface list while starting or running
		if starting || state.running != nil {
			status.SetText("[yellow]Running: stop before changing interfaces")
			return
		}
		ifaceList.Clear()
		ifaceList.AddItem("[yellow]Scanning interfaces... please wait", "", 0, nil)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					msg := fmt.Sprintf("PANIC in discovery: %v\nStack: %s", r, debug.Stack())
					log.Printf("%s", msg)
					// Try to show error in UI
					app.QueueUpdateDraw(func() {
						ifaceList.Clear()
						ifaceList.AddItem(fmt.Sprintf("[red]Scan crashed: %v", r), "", 0, nil)
						status.SetText("[red]Scanner crashed")
					})
				}
			}()

			choices, ips := scanInterfaces()

			app.QueueUpdateDraw(func() {
				state.choices = choices
				for k, v := range ips {
					state.ifaceIPs[k] = v
				}
				for _, c := range choices {
					if _, exists := state.selected[c.Name]; !exists {
						state.selected[c.Name] = false
					}
				}
				redrawList()
				updateButtons()
				if autoStart && state.canStart() {
					autoStartOnce.Do(func() { start() })
				}
			})
		}()
	}

	refreshBtn.SetSelectedFunc(func() {
		if starting || state.running != nil {
			status.SetText("[yellow]Running: stop before changing interfaces")
			return
		}
		refreshIfaces()
		updateButtons()
	})

	done := make(chan struct{})
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				app.QueueUpdateDraw(func() {
					if starting || state.running != nil {
						// Do not refresh/modify the interfaces list while running
						return
					}
					refreshIfaces()
					updateButtons()
				})
			case <-done:
				return
			}
		}
	}()

	quitBtn.SetSelectedFunc(func() {
		app.Stop()
	})

	updateButtons = func() {
		modeIdx, _ := modeDrop.GetCurrentOption()
		if modeIdx < 0 {
			modeIdx = 0
			modeDrop.SetCurrentOption(0)
		}
		state.mode = []string{modeBonding, modeLoadBalance}[modeIdx]
		serverDisabled := state.mode == modeLoadBalance
		if serverDisabled != serverFieldDisabled {
			serverField.SetDisabled(serverDisabled)
			suppressServerChange = true
			if serverDisabled {
				serverField.SetText("(unused in load-balance)")
			} else {
				serverField.SetText(state.server)
			}
			suppressServerChange = false
			serverFieldDisabled = serverDisabled
		}
		if !serverDisabled {
			state.server = strings.TrimSpace(serverField.GetText())
		}
		ok := state.canStart()
		if state.running == nil && !starting {
			startBtn.SetDisabled(!ok)
		}
		updateStatus()
	}

	setStatus := func(msg string) {
		app.QueueUpdateDraw(func() {
			status.SetText(msg)
		})
	}

	// setStatusDirect updates status without QueueUpdateDraw (safe before app.Run)
	setStatusDirect := func(msg string) {
		status.SetText(msg)
	}

	updateStatus = func() {
		selected := state.countSelected()
		if state.mode == modeBonding {
			state.server = strings.TrimSpace(serverField.GetText())
		}
		srv := state.server
		if state.mode == modeLoadBalance {
			srv = "(local)"
		}
		msg := fmt.Sprintf("Mode: %s | Server: %s | Selected IFs: %d", state.mode, srv, selected)

		var certErr error
		if state.mode == modeBonding {
			if name, err := detectClientCertName(state.pki); err != nil {
				certErr = err
				msg += " | Cert: [red]missing[-]"
			} else {
				msg += " | Cert: " + name
			}
		}

		var needs []string
		if state.mode == modeBonding {
			if state.server == "" {
				needs = append(needs, "server")
			}
			if certErr != nil {
				needs = append(needs, "client cert")
			}
		}
		if selected < 2 {
			needs = append(needs, ">=2 ifs")
		}
		if len(needs) > 0 {
			msg += " [yellow](need " + strings.Join(needs, ", ") + ")"
		}

		setStatusDirect(msg)
	}

	start = func() {
		if state.running != nil || starting {
			return
		}
		starting = true
		state.mode = state.currentMode(modeDrop)
		if state.mode == modeBonding {
			state.server = strings.TrimSpace(serverField.GetText())
		}
		if !state.canStart() {
			setStatus("[red]Select server and at least 2 interfaces (server only needed for bonding)")
			starting = false
			return
		}
		if state.mode == modeBonding {
			name, err := detectClientCertName(state.pki)
			if err != nil {
				setStatus(fmt.Sprintf("[red]%v", err))
				return
			}
			state.client = name
		}
		cfg := state.buildConfig()

		startBtn.SetDisabled(true)
		stopBtn.SetDisabled(true)
		// Prevent interface changes while starting/running
		refreshBtn.SetDisabled(true)

		var stopper func()
		// Clear usage text and show we're starting
		info.Clear()
		_, _ = fmt.Fprintf(info, "Starting %s mode...\n", cfg.Mode)
		runAsync(app, status, "Starting", func() error {
			log.Printf("start: calling startClientWithStats")
			fn, err := startClientWithStats(cfg, info, app)
			if err != nil {
				log.Printf("start: startClientWithStats failed: %v", err)
			} else {
				log.Printf("start: startClientWithStats OK")
			}
			if err == nil {
				stopper = fn
			}
			return err
		}, func(err error) {
			starting = false
			if err != nil {
				log.Printf("Start failed: %v", err)
				startBtn.SetDisabled(false)
				// Re-enable refresh on failure
				refreshBtn.SetDisabled(false)
				updateButtons()
				return
			}
			state.running = stopper
			saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Client: cfg.Client, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
			stopBtn.SetDisabled(false)
		})
	}

	stop := func() {
		if state.running != nil {
			stopBtn.SetDisabled(true)
			runAsync(app, status, "Stopping", func() error {
				state.running()
				state.running = nil
				return nil
			}, func(err error) {
				startBtn.SetDisabled(!state.canStart())
				// Allow interface changes again
				refreshBtn.SetDisabled(false)
				showUsageInInfo(info, state.mode)
				updateButtons()
			})
			return
		}
		startBtn.SetDisabled(!state.canStart())
		stopBtn.SetDisabled(true)
		refreshBtn.SetDisabled(false)
		setStatus("[yellow]stopped")
		updateButtons()
	}

	startBtn.SetSelectedFunc(start)
	stopBtn.SetSelectedFunc(stop)

	modeDrop.SetSelectedFunc(func(text string, idx int) {
		state.mode = text
		showUsageInInfo(info, state.mode)
		updateButtons()
	})

	serverField.SetChangedFunc(func(text string) {
		if suppressServerChange {
			return
		}
		state.server = strings.TrimSpace(text)
		if state.mode == modeBonding && state.server != "" {
			persistConfig()
		}
		updateButtons()
	})

	refreshIfaces()
	showUsageInInfo(info, state.mode)
	updateButtons()

	// key bindings
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		return event
	})

	if err := app.Run(); err != nil {
		log.Fatalf("tui error: %v", err)
	}
	close(done)
	ticker.Stop()
}

// tuiState holds UI selections and logic.
type tuiState struct {
	mode     string
	server   string
	client   string
	pki      string
	ctrl     int
	choices  []ifaceChoice
	selected map[string]bool
	running  func()

	ifaceIPs map[string]string
}

func newTUIState(initial clientConfig) *tuiState {
	st := &tuiState{
		mode:     initial.Mode,
		server:   initial.Server,
		client:   initial.Client,
		pki:      initial.PKI,
		ctrl:     initial.Ctrl,
		selected: make(map[string]bool),
		ifaceIPs: make(map[string]string),
		choices:  make([]ifaceChoice, 0),
	}
	for _, name := range initial.Ifaces {
		st.selected[name] = true
	}
	return st
}

func (s *tuiState) currentMode(drop *tview.DropDown) string {
	_, text := drop.GetCurrentOption()
	return text
}

func (s *tuiState) toggle(name string) {
	s.selected[name] = !s.selected[name]
}

func (s *tuiState) countSelected() int {
	count := 0
	for _, v := range s.selected {
		if v {
			count++
		}
	}
	return count
}

func (s *tuiState) canStart() bool {
	if s.mode == modeBonding && s.server == "" {
		return false
	}
	if s.mode == modeBonding {
		if _, err := detectClientCertName(s.pki); err != nil {
			return false
		}
	}
	count := s.countSelected()
	return count >= 2
}

func scanInterfaces() ([]ifaceChoice, map[string]string) {
	log.Printf("scanInterfaces: starting")
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("scanInterfaces: list interfaces failed: %v", err)
		return nil, nil
	}
	choices := make([]ifaceChoice, 0)
	ips := make(map[string]string)
	for _, iface := range ifaces {
		// filter: up, not loopback, has IPv4, skip obvious virtual (tap, tun, docker, veth)
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		lname := strings.ToLower(iface.Name)
		if strings.HasPrefix(lname, "lo") || strings.Contains(lname, "docker") || strings.Contains(lname, "veth") || strings.Contains(lname, "br-") || strings.Contains(lname, "tun") || strings.Contains(lname, "tap") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.To4() == nil {
				continue
			}
			log.Printf("scanInterfaces: checking %s", iface.Name)
			gw, _ := platform.GatewayForIface(tuiRunner{}, iface.Name)
			choices = append(choices, ifaceChoice{Name: iface.Name, IP: ipNet.IP.String(), HasGateway: gw != ""})
			ips[iface.Name] = ipNet.IP.String()
			break
		}
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].Name < choices[j].Name })
	log.Printf("scanInterfaces: found %d candidates", len(choices))
	return choices, ips
}

func (s *tuiState) buildConfig() clientConfig {
	ifaces := make([]string, 0)
	for name, on := range s.selected {
		if on {
			ifaces = append(ifaces, name)
		}
	}
	sort.Strings(ifaces)
	ips := make([]string, len(ifaces))
	for i, n := range ifaces {
		ips[i] = s.ifaceIPs[n]
	}
	server := s.server
	return clientConfig{
		Server: server,
		Ifaces: ifaces,
		IPs:    ips,
		Conns:  len(ifaces),
		Mode:   s.mode,
		PKI:    s.pki,
		Client: s.client,
		Ctrl:   s.ctrl,
	}
}

// runAsync mirrors the server TUI spinner to keep UI responsive during slow ops.
func runAsync(app *tview.Application, status *tview.TextView, label string, work func() error, onDone func(err error)) {
	frames := []rune{'|', '/', '-', '\\'}
	stop := make(chan struct{})
	go func() {
		i := 0
		for {
			select {
			case <-stop:
				return
			case <-time.After(120 * time.Millisecond):
				frame := frames[i%len(frames)]
				i++
				app.QueueUpdateDraw(func() {
					status.SetText(fmt.Sprintf("[yellow]%s %c", label, frame))
				})
			}
		}
	}()

	go func() {
		err := work()
		close(stop)
		app.QueueUpdateDraw(func() {
			if err != nil {
				status.SetText(fmt.Sprintf("[red]%s failed: %v", label, err))
				// Also surface the error to the info pane if available.
				if status != nil {
					// no-op; status already set
				}
			} else {
				status.SetText(fmt.Sprintf("[green]%s done", label))
			}
			if onDone != nil {
				onDone(err)
			}
		})
	}()
}

type tuiLogWriter struct {
	app  *tview.Application
	view *tview.TextView
}

func (w *tuiLogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Write to file as well for debugging
	if exe, err := os.Executable(); err == nil {
		logFile := filepath.Join(filepath.Dir(exe), "client_debug.log")
		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if f != nil {
			// Strip colors/tags if possible, but raw log is fine
			fmt.Fprintf(f, "%s %s", time.Now().Format("15:04:05"), msg)
			f.Close()
		}
	}
	w.app.QueueUpdateDraw(func() {
		_, _ = w.view.Write([]byte(msg))
		w.view.ScrollToEnd()
	})
	return len(p), nil
}

func showUsageInInfo(info *tview.TextView, mode string) {
	var help string
	if mode == modeBonding {
		help = `[yellow]BONDING MODE[white]
• Server-backed multipath VPN
• TUN at 10.8.0.x/24
• Requires server + client cert

[gray]Waiting for connection stats...`
	} else {
		help = `[yellow]LOAD-BALANCE MODE[white]
• Local multipath routing (no TUN)
• Installs multipath default route over selected gateways
• Adds MASQUERADE per uplink; no server required

[gray]Waiting for connection stats...`
	}
	info.SetText(help)
}
