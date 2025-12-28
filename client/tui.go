package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"fluxify/client/platform"
	"fluxify/common"
)

type ifaceChoice struct {
	Name       string
	IP         string
	MTU        int
	Gw         string
	Gw6        string
	HasGateway bool
	Up         bool
	Loopback   bool
	Virtual    bool
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
func runTUI(initial clientConfig) {
	app := tview.NewApplication()
	app.EnableMouse(true)
	app.EnablePaste(true)

	state := newTUIState(initial)

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
	ifaceList.SetSelectedBackgroundColor(tcell.ColorDarkSlateGray)
	ifaceList.SetSelectedTextColor(tcell.ColorWhite)

	usageView := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true).SetWrap(true)
	usageView.SetBorder(true).SetTitle("Usage")
	usageView.SetScrollable(true)

	logView := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true).SetWrap(true)
	logView.SetBorder(true).SetTitle("Logs")
	logView.SetScrollable(true)
	log.SetOutput(&tuiLogWriter{app: app, view: logView})

	statusBar := tview.NewTextView().SetDynamicColors(true)
	statusBar.SetBorder(true).SetTitle("Status")
	statusBar.SetWrap(true)
	statusBar.SetWordWrap(true)
	statusBar.SetScrollable(true)

	actionStatus := tview.NewTextView().SetDynamicColors(true).SetText("Idle")
	actionStatus.SetBorder(true).SetTitle("Activity")

	styleActionBtn := func(b *tview.Button, bg tcell.Color) {
		b.SetBorder(false)
		b.SetBackgroundColor(bg)
		b.SetLabelColor(tcell.ColorWhite)
		b.SetLabelColorActivated(tcell.ColorYellow)
	}

	startBtn := tview.NewButton(" START ")
	styleActionBtn(startBtn, tcell.ColorDarkGreen)
	stopBtn := tview.NewButton(" STOP ")
	styleActionBtn(stopBtn, tcell.ColorDarkRed)
	stopBtn.SetDisabled(true)
	diagBtn := tview.NewButton(" DIAG ")
	styleActionBtn(diagBtn, tcell.ColorDarkBlue)
	quitBtn := tview.NewButton(" QUIT ")
	styleActionBtn(quitBtn, tcell.ColorDarkSlateGray)

	// Layout: top row = Config (left 1/2) + Actions (right 1/2)
	configBox := tview.NewFlex().SetDirection(tview.FlexRow)
	configBox.SetBorder(true).SetTitle("Config")
	configBox.AddItem(modeDrop, 1, 0, false)
	configBox.AddItem(serverField, 1, 0, false)

	filterUp := true
	filterGateway := true
	filterNonVirtual := true

	filterUpBox := tview.NewCheckbox().SetLabel("Up ").SetChecked(true)
	filterGatewayBox := tview.NewCheckbox().SetLabel("Gateway ").SetChecked(true)
	filterNonVirtualBox := tview.NewCheckbox().SetLabel("Non-virtual ").SetChecked(true)
	filtersRow := tview.NewFlex().SetDirection(tview.FlexRow)
	filtersRow.AddItem(filterUpBox, 1, 0, false)
	filtersRow.AddItem(filterGatewayBox, 1, 0, false)
	filtersRow.AddItem(filterNonVirtualBox, 1, 0, false)
	configBox.AddItem(filtersRow, 3, 0, false)

	actionsBox := tview.NewFlex().SetDirection(tview.FlexRow)
	actionsBox.SetBorder(true).SetTitle("Actions")
	actionsBox.AddItem(tview.NewBox(), 0, 1, false) // top spacer
	actionsBox.AddItem(startBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 1, 0, false)
	actionsBox.AddItem(stopBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 1, 0, false)
	actionsBox.AddItem(diagBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 1, 0, false)
	actionsBox.AddItem(quitBtn, 1, 0, false)
	actionsBox.AddItem(tview.NewBox(), 0, 1, false) // bottom spacer

	topRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	topRow.AddItem(configBox, 0, 1, false)
	topRow.AddItem(actionsBox, 0, 1, false)

	infoRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	infoRow.AddItem(usageView, 0, 1, false)
	infoRow.AddItem(logView, 0, 1, false)

	// Main layout
	form := tview.NewFlex().SetDirection(tview.FlexRow)
	form.AddItem(topRow, 9, 0, false)
	form.AddItem(statusBar, 6, 0, false)
	form.AddItem(ifaceList, 0, 3, true)
	form.AddItem(infoRow, 0, 2, false)
	form.AddItem(actionStatus, 3, 0, false)

	app.SetRoot(form, true).SetFocus(ifaceList)

	// Populate interfaces
	var refreshIfaces func()
	var redrawList func()
	var updateButtons func()
	var updateStatus func()
	var persistConfig func()
	var start func()
	var stop func(exit bool)
	var requestQuit func()
	var scanInFlight bool
	var startWatchCancel func()
	var quitRequested bool

	mouseEnabled := true
	lastError := ""
	serverFieldDisabled := false
	suppressServerChange := false
	var starting bool // prevent multiple concurrent starts and preserve stats panel
	filtersActive := func() bool {
		return !starting && state.running == nil
	}
	displayChoices := func() []ifaceChoice {
		if filtersActive() {
			return state.choices
		}
		choices := make([]ifaceChoice, 0, len(state.choices))
		for _, c := range state.choices {
			if state.selected[c.Name] || strings.EqualFold(c.Name, "fluxify") {
				choices = append(choices, c)
			}
		}
		return choices
	}

	persistConfig = func() {
		if starting || state.running != nil {
			return
		}
		cfg := state.buildConfig()
		saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Cert: cfg.Cert, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
	}

	redrawList = func() {
		ifaceList.Clear()
		applyFilters := filtersActive()
		for _, c := range displayChoices() {
			if applyFilters && filterUp && !c.Up {
				continue
			}
			if applyFilters && filterGateway && !c.HasGateway {
				continue
			}
			if applyFilters && filterNonVirtual && (c.Virtual || c.Loopback) {
				continue
			}
			checked := state.selected[c.Name]
			ext := externalLabelFor(state, c)
			label := formatIfaceLabel(c, ext)
			selTag := "[gray]---[white]"
			if checked {
				selTag = "[green]SEL[white]"
			}
			availTag := "[green]OK[white]"
			if !ifaceSelectable(c) {
				if filtersActive() {
					state.selected[c.Name] = false
				}
				availTag = "[red]NO[white]"
			}
			line := fmt.Sprintf("%s %s %s", selTag, availTag, label)
			choice := c
			ifaceList.AddItem(line, "", 0, func() {
				// Block toggles while running
				if state.running != nil {
					actionStatus.SetText("[yellow]Running: stop before changing interfaces")
					return
				}
				if !ifaceSelectable(choice) {
					actionStatus.SetText("[red]Interface unavailable; pick another")
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
		// Do not allow modifying interface list while running
		if state.running != nil || starting {
			return
		}
		if scanInFlight {
			return
		}
		scanInFlight = true
		actionStatus.SetText("[yellow]Scanning interfaces...")
		if len(state.choices) == 0 {
			ifaceList.Clear()
			ifaceList.AddItem("[yellow]Scanning interfaces... please wait", "", 0, nil)
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					msg := fmt.Sprintf("PANIC in discovery: %v\nStack: %s", r, debug.Stack())
					log.Printf("%s", msg)
					// Try to show error in UI
					app.QueueUpdateDraw(func() {
						if len(state.choices) == 0 {
							ifaceList.Clear()
							ifaceList.AddItem(fmt.Sprintf("[red]Scan crashed: %v", r), "", 0, nil)
						}
						actionStatus.SetText("[red]Scanner crashed")
						scanInFlight = false
					})
				}
			}()

			choices, ips := scanInterfaces()

			app.QueueUpdateDraw(func() {
				scanInFlight = false
				if state.running != nil || starting {
					return
				}
				state.choices = choices
				for k, v := range ips {
					state.ifaceIPs[k] = v
				}
				for _, c := range choices {
					if _, exists := state.selected[c.Name]; !exists {
						state.selected[c.Name] = false
					}
				}
				if len(choices) == 0 {
					ifaceList.Clear()
					ifaceList.AddItem("[red]No interfaces found", "", 0, nil)
				} else {
					redrawList()
				}
				updateButtons()
				if filtersActive() {
					queueExternalIPChecks(app, state, choices, redrawList, updateButtons)
				}
				actionStatus.SetText("Idle")
			})
		}()
	}

	diagBtn.SetSelectedFunc(func() {
		cfg := clientConfig{
			Server: strings.TrimSpace(serverField.GetText()),
			Mode:   state.mode,
			PKI:    state.pki,
			Cert:   state.cert,
			Ctrl:   state.ctrl,
		}
		var report diagReport
		runAsync(app, actionStatus, "Diagnosing", func() error {
			report, _ = runDiagnostics(cfg)
			return report.err
		}, func(err error) {
			appendLog(app, logView, "\n"+report.details+"\n")
			appendDiagnosticsLog(report.details)
			lastError = report.errString()
			if report.summary != "" {
				if report.err != nil {
					actionStatus.SetText("[red]" + report.summary)
				} else {
					actionStatus.SetText("[green]" + report.summary)
				}
			}
			updateStatus()
		})
	})

	done := make(chan struct{})
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				app.QueueUpdateDraw(func() {
					if state.running != nil {
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
		filtersOn := filtersActive()
		filterUpBox.SetDisabled(!filtersOn)
		filterGatewayBox.SetDisabled(!filtersOn)
		filterNonVirtualBox.SetDisabled(!filtersOn)
		if filtersOn {
			ifaceList.SetTitle("Interfaces (select with mouse/Enter)")
		} else {
			ifaceList.SetTitle("Interfaces (locked while running)")
		}
		redrawList()
		ok := state.canStart()
		if state.running == nil && !starting {
			startBtn.SetDisabled(!ok)
		}
		updateStatus()
		showUsageInUsage(usageView, state, starting)
	}

	filterUpBox.SetChangedFunc(func(checked bool) {
		filterUp = checked
		redrawList()
		updateButtons()
	})
	filterGatewayBox.SetChangedFunc(func(checked bool) {
		filterGateway = checked
		redrawList()
		updateButtons()
	})
	filterNonVirtualBox.SetChangedFunc(func(checked bool) {
		filterNonVirtual = checked
		redrawList()
		updateButtons()
	})

	setActionStatus := func(msg string) {
		actionStatus.SetText(msg)
	}

	resetStartState := func(err error) {
		starting = false
		if startWatchCancel != nil {
			startWatchCancel()
			startWatchCancel = nil
		}
		state.running = nil
		stopBtn.SetDisabled(true)
		if err != nil {
			lastError = err.Error()
			setActionStatus("[red]" + err.Error())
		} else {
			lastError = ""
			setActionStatus("Idle")
		}
		showUsageInUsage(usageView, state, starting)
		updateButtons()
		if quitRequested {
			quitRequested = false
			app.Stop()
		}
	}

	summarizeList := func(items []string, limit int) string {
		if len(items) == 0 {
			return ""
		}
		if len(items) <= limit {
			return strings.Join(items, ", ")
		}
		return strings.Join(items[:limit], ", ") + fmt.Sprintf(" +%d", len(items)-limit)
	}

	collectWarnings := func() []string {
		warnings := make([]string, 0)
		extCounts := make(map[string]int)
		for _, c := range state.choices {
			if !state.selected[c.Name] {
				continue
			}
			if !c.Up {
				warnings = append(warnings, c.Name+" down")
				continue
			}
			if !c.HasGateway {
				warnings = append(warnings, c.Name+" no gw")
			}
			if c.IP == "" {
				warnings = append(warnings, c.Name+" no ip")
			}
			if errMsg := state.extErr[c.Name]; errMsg != "" {
				warnings = append(warnings, c.Name+" ext ip err")
			}
			if ext := state.extIP[c.Name]; ext != "" {
				extCounts[ext]++
			}
		}
		for ip, count := range extCounts {
			if count >= 2 {
				warnings = append(warnings, fmt.Sprintf("same ext ip: %s (%d ifs)", ip, count))
			}
		}
		return warnings
	}

	setMouseEnabled := func(enabled bool) {
		mouseEnabled = enabled
		app.EnableMouse(enabled)
		if updateStatus != nil {
			updateStatus()
		}
	}

	// setStatusBarDirect updates status bar without QueueUpdateDraw (safe before app.Run)
	setStatusBarDirect := func(msg string) {
		statusBar.SetText(msg)
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
		choices := displayChoices()
		applyFilters := filtersActive()
		visibleCount := countVisibleChoices(choices, filterUp && applyFilters, filterGateway && applyFilters, filterNonVirtual && applyFilters)
		visibleSelected := countVisibleSelected(choices, state.selected, filterUp && applyFilters, filterGateway && applyFilters, filterNonVirtual && applyFilters)
		stateLabel := "IDLE"
		stateColor := "[white]"
		if starting {
			stateLabel = "STARTING"
			stateColor = "[yellow]"
		} else if state.running != nil {
			stateLabel = "RUNNING"
			stateColor = "[green]"
		}
		mouseLabel := "OFF"
		if mouseEnabled {
			mouseLabel = "ON"
		}
		line1 := fmt.Sprintf("State: %s%s[white] | Mode: %s | IFs: %d (%d/%d shown) | Server: %s | Mouse: %s",
			stateColor, stateLabel, state.mode, selected, visibleSelected, visibleCount, srv, mouseLabel)

		var certErr error
		var certName string
		var caName string
		if state.mode == modeBonding {
			if bundlePath, err := detectClientBundlePath(state.pki); err != nil {
				certErr = err
			} else {
				certName = bundleBaseName(bundlePath)
				caName, _ = bundleCAName(bundlePath)
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

		warnings := collectWarnings()
		warnText := summarizeList(warnings, 2)

		line2 := "[green]OK[white]"
		if len(needs) > 0 {
			line2 = "[red]BLOCKED[white]: " + strings.Join(needs, ", ")
		} else if state.mode == modeBonding && certName != "" {
			line2 = "[green]OK[white]: cert " + certName
		}
		if state.mode == modeBonding {
			if certErr != nil {
				line2 += " | CA: missing"
			} else if caName != "" {
				line2 += " | CA: " + caName
			} else {
				line2 += " | CA: unknown"
			}
		}
		if warnText != "" {
			line2 += " | [yellow]Warn[white]: " + warnText
		}
		if lastError != "" {
			line2 += " | [red]Err[white]: " + lastError
		}

		setStatusBarDirect(line1 + "\n" + line2)
	}

	start = func() {
		if state.running != nil || starting {
			return
		}
		starting = true
		if startWatchCancel != nil {
			startWatchCancel()
			startWatchCancel = nil
		}
		lastError = ""
		state.mode = state.currentMode(modeDrop)
		if state.mode == modeBonding {
			state.server = strings.TrimSpace(serverField.GetText())
		}
		if !state.canStart() {
			setActionStatus("[red]Select server and at least 2 interfaces (server only needed for bonding)")
			starting = false
			updateButtons()
			return
		}
		if state.mode == modeBonding {
			path, err := detectClientBundlePath(state.pki)
			if err != nil {
				resetStartState(err)
				return
			}
			state.cert = path
		}
		cfg := state.buildConfig()

		startBtn.SetDisabled(true)
		stopBtn.SetDisabled(true)
		var stopper func()
		log.Printf("Starting %s mode...", cfg.Mode)

		// Watchdog: force-reset UI if start hangs longer than controlTimeout+5s
		{
			watchCtx, cancelWatch := context.WithCancel(context.Background())
			startWatchCancel = cancelWatch
			go func() {
				select {
				case <-time.After(controlTimeout + 5*time.Second):
					app.QueueUpdateDraw(func() {
						if starting && state.running == nil {
							resetStartState(fmt.Errorf("start timeout: no response from control plane"))
						}
					})
				case <-watchCtx.Done():
				}
			}()
		}

		runAsync(app, actionStatus, "Starting", func() error {
			vlogf("start: calling startClientWithStats")
			fn, err := startClientWithStats(cfg, usageView, app)
			if err != nil {
				vlogf("start: startClientWithStats failed: %v", err)
			} else {
				vlogf("start: startClientWithStats OK")
			}
			if err == nil {
				stopper = fn
			}
			return err
		}, func(err error) {
			if err != nil {
				resetStartState(err)
				return
			}
			lastError = ""
			starting = false
			state.running = stopper
			log.Printf("Started %s with %d interfaces.", cfg.Mode, len(cfg.Ifaces))
			saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Cert: cfg.Cert, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
			stopBtn.SetDisabled(false)
			if quitRequested {
				quitRequested = false
				stop(true)
			}
		})
	}

	stop = func(exit bool) {
		if state.running != nil {
			stopBtn.SetDisabled(true)
			runAsync(app, actionStatus, "Stopping", func() error {
				state.running()
				state.running = nil
				return nil
			}, func(err error) {
				startBtn.SetDisabled(!state.canStart())
				showUsageInUsage(usageView, state, starting)
				log.Printf("Stopped.")
				updateButtons()
				if exit {
					app.Stop()
				}
			})
			return
		}
		startBtn.SetDisabled(!state.canStart())
		stopBtn.SetDisabled(true)
		setActionStatus("[yellow]stopped")
		updateButtons()
		if exit {
			app.Stop()
		}
	}

	requestQuit = func() {
		if starting && state.running == nil {
			quitRequested = true
			setActionStatus("[yellow]Stopping...")
			return
		}
		stop(true)
	}

	startBtn.SetSelectedFunc(start)
	stopBtn.SetSelectedFunc(func() { stop(false) })
	quitBtn.SetSelectedFunc(requestQuit)

	modeDrop.SetSelectedFunc(func(text string, idx int) {
		state.mode = text
		showUsageInUsage(usageView, state, starting)
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
	showUsageInUsage(usageView, state, starting)
	updateButtons()

	// key bindings
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			requestQuit()
			return nil
		}
		if event.Key() == tcell.KeyEscape {
			requestQuit()
			return nil
		}
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q', 'Q':
				requestQuit()
				return nil
			}
		}
		if event.Key() == tcell.KeyF2 {
			setMouseEnabled(!mouseEnabled)
			return nil
		}
		return event
	})

	defer func() {
		if state.running != nil {
			state.running()
			state.running = nil
		}
	}()
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
	cert     string
	pki      string
	ctrl     int
	dns4     []string
	dns6     []string
	choices  []ifaceChoice
	selected map[string]bool
	running  func()

	ifaceIPs map[string]string
	extIP    map[string]string
	extErr   map[string]string
	extAt    map[string]time.Time
	extBusy  map[string]bool
}

func newTUIState(initial clientConfig) *tuiState {
	st := &tuiState{
		mode:     initial.Mode,
		server:   initial.Server,
		cert:     initial.Cert,
		pki:      initial.PKI,
		ctrl:     initial.Ctrl,
		dns4:     initial.DNS4,
		dns6:     initial.DNS6,
		selected: make(map[string]bool),
		ifaceIPs: make(map[string]string),
		choices:  make([]ifaceChoice, 0),
		extIP:    make(map[string]string),
		extErr:   make(map[string]string),
		extAt:    make(map[string]time.Time),
		extBusy:  make(map[string]bool),
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
	vlogf("scanInterfaces: starting")
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("scanInterfaces: list interfaces failed: %v", err)
		return nil, nil
	}
	choices := make([]ifaceChoice, 0)
	ips := make(map[string]string)
	for _, iface := range ifaces {
		up := iface.Flags&net.FlagUp != 0
		loopback := iface.Flags&net.FlagLoopback != 0
		virtual := isVirtualIfaceName(iface.Name)
		addrs, _ := iface.Addrs()
		ip := ""
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			if v4 := ipNet.IP.To4(); v4 != nil {
				ip = v4.String()
				break
			}
		}
		gw := ""
		gw6 := ""
		if up && !loopback {
			vlogf("scanInterfaces: checking %s", iface.Name)
			gw, _ = platform.GatewayForIface(tuiRunner{}, iface.Name)
			gw6, _ = platform.GatewayForIface6(tuiRunner{}, iface.Name)
		}
		hasGateway := gw != "" || gw6 != ""
		if ip == "" && !hasGateway && !up {
			continue
		}
		choices = append(choices, ifaceChoice{
			Name:       iface.Name,
			IP:         ip,
			MTU:        iface.MTU,
			Gw:         gw,
			Gw6:        gw6,
			HasGateway: hasGateway,
			Up:         up,
			Loopback:   loopback,
			Virtual:    virtual,
		})
		if ip != "" {
			ips[iface.Name] = ip
		}
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].Name < choices[j].Name })
	vlogf("scanInterfaces: found %d candidates", len(choices))
	return choices, ips
}

func isVirtualIfaceName(name string) bool {
	lname := strings.ToLower(name)
	return strings.HasPrefix(lname, "lo") ||
		strings.Contains(lname, "docker") ||
		strings.Contains(lname, "veth") ||
		strings.Contains(lname, "br-") ||
		strings.Contains(lname, "tun") ||
		strings.Contains(lname, "tap")
}

func ifaceSelectable(c ifaceChoice) bool {
	if !c.HasGateway || !c.Up {
		return false
	}
	if c.Virtual || c.Loopback {
		return false
	}
	return true
}

func formatIfaceLabel(c ifaceChoice, ext string) string {
	ip := c.IP
	if ip == "" {
		ip = "-"
	}
	gw := "-"
	if c.Gw != "" {
		gw = c.Gw
	}
	if c.Gw6 != "" {
		if gw == "-" {
			gw = c.Gw6
		} else {
			gw = gw + "/" + c.Gw6
		}
	}
	ip = truncate(ip, 18)
	gw = truncate(gw, 22)
	ext = truncate(ext, 15)
	state := "[red]DOWN"
	if c.Up {
		state = "[green]UP"
	}
	flags := ""
	if c.Virtual || c.Loopback {
		flags = " [gray](virt)"
	}
	return fmt.Sprintf("%-10s %-18s mtu:%4d gw:%-22s ext:%-15s %s[white]%s", c.Name, ip, c.MTU, gw, ext, state, flags)
}

func externalLabelFor(st *tuiState, c ifaceChoice) string {
	if c.IP == "" || !c.Up || !c.HasGateway {
		return "-"
	}
	if st.extBusy[c.Name] {
		return "..."
	}
	if ip := st.extIP[c.Name]; ip != "" {
		return ip
	}
	if st.extErr[c.Name] != "" {
		return "err"
	}
	return "..."
}

func queueExternalIPChecks(app *tview.Application, st *tuiState, choices []ifaceChoice, redrawList func(), updateButtons func()) {
	now := time.Now()
	for _, c := range choices {
		if c.IP == "" || !c.Up || !c.HasGateway {
			continue
		}
		if st.extBusy[c.Name] {
			continue
		}
		if at, ok := st.extAt[c.Name]; ok && now.Sub(at) < 60*time.Second {
			continue
		}
		name := c.Name
		localIP := c.IP
		st.extBusy[name] = true
		go func() {
			ip, err := fetchExternalIP(localIP)
			app.QueueUpdateDraw(func() {
				st.extBusy[name] = false
				st.extAt[name] = time.Now()
				if err != nil {
					vlogf("external ip (%s): %v", name, err)
					st.extErr[name] = err.Error()
					st.extIP[name] = ""
				} else {
					st.extErr[name] = ""
					st.extIP[name] = ip
				}
				redrawList()
				updateButtons()
			})
		}()
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func fetchExternalIP(localIP string) (string, error) {
	if localIP == "" {
		return "", fmt.Errorf("no local ip")
	}
	ip := net.ParseIP(localIP)
	if ip == nil {
		return "", fmt.Errorf("invalid local ip: %s", localIP)
	}
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: &net.TCPAddr{IP: ip},
	}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ext := strings.TrimSpace(string(body))
	if net.ParseIP(ext) == nil {
		return "", fmt.Errorf("invalid response: %q", ext)
	}
	return ext, nil
}

type diagReport struct {
	summary string
	details string
	err     error
}

func (d diagReport) errString() string {
	if d.err == nil {
		return ""
	}
	if d.summary != "" {
		return d.summary
	}
	return d.err.Error()
}

func runDiagnostics(cfg clientConfig) (diagReport, error) {
	lines := []string{"[yellow]PPP Fluxify Diagnostics PPP[white]"}
	lines = append(lines, fmt.Sprintf("Time: %s", time.Now().Format("2006-01-02 15:04:05")))
	lines = append(lines, fmt.Sprintf("OS: %s/%s", runtime.GOOS, runtime.GOARCH))
	lines = append(lines, "")

	// System Information
	lines = append(lines, "[cyan] System [white]")
	lines = append(lines, fmt.Sprintf("  Go version: %s", runtime.Version()))
	lines = append(lines, fmt.Sprintf("  NumCPU: %d", runtime.NumCPU()))
	lines = append(lines, fmt.Sprintf("  NumGoroutine: %d", runtime.NumGoroutine()))
	lines = append(lines, "")

	// Interface Discovery
	lines = append(lines, "[cyan] Interfaces [white]")
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		stateTag := "[red]DOWN[white]"
		if iface.Flags&net.FlagUp != 0 {
			stateTag = "[green]UP[white]"
		}
		addrs, _ := iface.Addrs()
		var ipv4, ipv6 string
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP != nil {
				if v4 := ipNet.IP.To4(); v4 != nil {
					ipv4 = v4.String()
				} else if ipv6 == "" {
					ipv6 = ipNet.IP.String()
				}
			}
		}
		if ipv4 == "" {
			ipv4 = "-"
		}
		lines = append(lines, fmt.Sprintf("  %s %s MTU:%d IPv4:%s", iface.Name, stateTag, iface.MTU, ipv4))

		// Gateway detection
		if iface.Flags&net.FlagUp != 0 {
			gw, _ := platform.GatewayForIface(tuiRunner{}, iface.Name)
			if gw != "" {
				lines = append(lines, fmt.Sprintf("    Gateway: %s", gw))
			}
		}
	}
	lines = append(lines, "")

	// Server Connectivity (only for bonding mode)
	if cfg.Server == "" {
		lines = append(lines, "[cyan] Server [white]")
		lines = append(lines, "  [yellow]Server not configured (load-balance mode?)[white]")
		lines = append(lines, "")
		lines = append(lines, "[yellow]Routing[white]")
		lines = appendRouteDump(lines)
		report := diagReport{summary: "diagnostics ok (no server)", details: strings.Join(lines, "\n"), err: nil}
		return report, nil
	}

	host, port, err := parseServerAddr(cfg.Server, cfg.Ctrl)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[red]Server: %v[white]", err))
		return diagReport{summary: "invalid server", details: strings.Join(lines, "\n"), err: err}, err
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	lines = append(lines, "[cyan] Server Connectivity [white]")
	lines = append(lines, fmt.Sprintf("  Target: %s", addr))

	// DNS resolution
	if ip := net.ParseIP(host); ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			lines = append(lines, fmt.Sprintf("  [yellow]DNS: failed (%v)[white]", err))
		} else if len(ips) > 0 {
			var ipStrs []string
			for _, ip := range ips {
				ipStrs = append(ipStrs, ip.String())
			}
			lines = append(lines, "  [green]DNS: "+strings.Join(ipStrs, ", ")+"[white]")
		}
	}

	// TCP connectivity with timing
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  [red]TCP: failed (%s)[white]", err))
		lines = append(lines, "")
		lines = append(lines, "[yellow]Routing[white]")
		lines = appendRouteDump(lines)
		report := diagReport{summary: "tcp connect failed", details: strings.Join(lines, "\n"), err: err}
		return report, err
	}
	tcpLatency := time.Since(start)
	_ = conn.Close()
	lines = append(lines, fmt.Sprintf("  [green]TCP: ok (latency: %s)[white]", tcpLatency.Round(time.Millisecond)))

	// Certificate checks
	lines = append(lines, "")
	lines = append(lines, "[cyan] Certificates [white]")
	bundlePath := cfg.Cert
	if bundlePath == "" {
		bundlePath, err = detectClientBundlePath(cfg.PKI)
	}
	if err != nil {
		lines = append(lines, fmt.Sprintf("  [red]Bundle: %v[white]", err))
		lines = append(lines, "")
		lines = append(lines, "[yellow]Routing[white]")
		lines = appendRouteDump(lines)
		report := diagReport{summary: "bundle missing", details: strings.Join(lines, "\n"), err: err}
		return report, err
	}
	lines = append(lines, "  Bundle: "+bundlePath)
	if name := bundleBaseName(bundlePath); name != "" {
		lines = append(lines, "  Cert CN: "+name)
	}
	if caName, err := bundleCAName(bundlePath); err == nil && caName != "" {
		lines = append(lines, "  CA CN: "+caName)
	}

	// TLS handshake
	lines = append(lines, "")
	lines = append(lines, "[cyan] TLS Handshake [white]")
	tlsCfg, err := clientTLSConfig(cfg)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  [red]TLS config: %v[white]", err))
		lines = append(lines, "")
		lines = append(lines, "[yellow]Routing[white]")
		lines = appendRouteDump(lines)
		report := diagReport{summary: "tls config failed", details: strings.Join(lines, "\n"), err: err}
		return report, err
	}
	if host != "" {
		c := tlsCfg.Clone()
		c.ServerName = host
		tlsCfg = c
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	start = time.Now()
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  [red]TLS: tcp connect failed (%s)[white]", err))
		lines = append(lines, "")
		lines = append(lines, "[yellow]Routing[white]")
		lines = appendRouteDump(lines)
		report := diagReport{summary: "tls tcp failed", details: strings.Join(lines, "\n"), err: err}
		return report, err
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		tlsErr := classifyTLSError(err)
		lines = append(lines, fmt.Sprintf("  [red]TLS: handshake failed[white]"))
		lines = append(lines, fmt.Sprintf("  [red]  Error: %s[white]", tlsErr))
		lines = append(lines, "")
		lines = append(lines, "[yellow]Routing[white]")
		lines = appendRouteDump(lines)
		report := diagReport{summary: "tls failed", details: strings.Join(lines, "\n"), err: tlsErr}
		return report, tlsErr
	}
	tlsLatency := time.Since(start)
	connState := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	lines = append(lines, fmt.Sprintf("  [green]TLS: ok (latency: %s)[white]", tlsLatency.Round(time.Millisecond)))
	lines = append(lines, fmt.Sprintf("  Version: TLS %s", tlsVersionName(connState.Version)))
	lines = append(lines, fmt.Sprintf("  Cipher: %s", tls.CipherSuiteName(connState.CipherSuite)))

	// Path MTU probe
	lines = append(lines, "")
	lines = append(lines, "[cyan] Path MTU Probe [white]")
	pmtuResult := common.ProbePMTUD(host, 1400, 3*time.Second)
	if pmtuResult.Success {
		lines = append(lines, fmt.Sprintf("  [green]%s[white]", common.FormatPMTUDResult(pmtuResult)))
	} else {
		lines = append(lines, fmt.Sprintf("  [yellow]%s[white]", common.FormatPMTUDResult(pmtuResult)))
		if pmtuResult.SuggestMTU > 0 {
			lines = append(lines, fmt.Sprintf("  [yellow]Suggestion: use -mtu=%d[white]", pmtuResult.SuggestMTU))
		}
	}

	// Routing
	lines = append(lines, "")
	lines = append(lines, "[cyan] Routing [white]")
	lines = appendRouteDump(lines)

	// Performance recommendations
	lines = append(lines, "")
	lines = append(lines, "[cyan] Recommendations [white]")
	recommendations := collectRecommendations(tcpLatency, pmtuResult)
	if len(recommendations) == 0 {
		lines = append(lines, "  [green]No issues detected[white]")
	} else {
		for _, rec := range recommendations {
			lines = append(lines, "  "+rec)
		}
	}

	report := diagReport{summary: "diagnostics ok", details: strings.Join(lines, "\n"), err: nil}
	return report, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

func collectRecommendations(tcpLatency time.Duration, pmtu common.PMTUDResult) []string {
	var recs []string

	if tcpLatency > 200*time.Millisecond {
		recs = append(recs, fmt.Sprintf("[yellow]High latency (%s): consider using -reorder-flush-timeout=%s[white]",
			tcpLatency.Round(time.Millisecond), (tcpLatency+30*time.Millisecond).Round(10*time.Millisecond)))
	}

	if !pmtu.Success && pmtu.SuggestMTU > 0 {
		recs = append(recs, fmt.Sprintf("[yellow]MTU issues detected: use -mtu=%d or -probe-pmtud[white]", pmtu.SuggestMTU))
	}

	if runtime.GOOS == "linux" {
		// Check socket buffer sizes (Linux only)
		recs = appendLinuxRecommendations(recs)
	}

	return recs
}

func appendLinuxRecommendations(recs []string) []string {
	// Try to read sysctl values
	rmem, _ := os.ReadFile("/proc/sys/net/core/rmem_max")
	if len(rmem) > 0 {
		var rmemVal int
		if _, err := fmt.Sscanf(string(rmem), "%d", &rmemVal); err == nil && rmemVal < 26214400 {
			recs = append(recs, "[yellow]Low rmem_max: sudo sysctl -w net.core.rmem_max=26214400[white]")
		}
	}
	wmem, _ := os.ReadFile("/proc/sys/net/core/wmem_max")
	if len(wmem) > 0 {
		var wmemVal int
		if _, err := fmt.Sscanf(string(wmem), "%d", &wmemVal); err == nil && wmemVal < 26214400 {
			recs = append(recs, "[yellow]Low wmem_max: sudo sysctl -w net.core.wmem_max=26214400[white]")
		}
	}
	return recs
}

func appendRouteDump(lines []string) []string {
	if runtime.GOOS == "windows" {
		lines = append(lines, "[cyan]IPv4 routes (route print -4):[white]")
		lines = appendCommandOutput(lines, "route", "print", "-4")
		lines = append(lines, "[cyan]IPv6 routes (netsh interface ipv6 show route):[white]")
		lines = appendCommandOutput(lines, "netsh", "interface", "ipv6", "show", "route")
		return lines
	}
	lines = append(lines, "[cyan]IPv4 routes (ip route):[white]")
	lines = appendCommandOutput(lines, "ip", "route")
	lines = append(lines, "[cyan]IPv6 routes (ip -6 route):[white]")
	lines = appendCommandOutput(lines, "ip", "-6", "route")
	return lines
}

func appendCommandOutput(lines []string, name string, args ...string) []string {
	out, err := common.RunPrivilegedOutput(name, args...)
	if err != nil {
		lines = append(lines, fmt.Sprintf("[red]%s %s failed: %v[white]", name, strings.Join(args, " "), err))
		return lines
	}
	text := strings.TrimRight(string(out), "\r\n")
	if text == "" {
		lines = append(lines, "[gray](no output)[white]")
		return lines
	}
	for _, line := range strings.Split(text, "\n") {
		lines = append(lines, line)
	}
	return lines
}

func bundleCAName(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var certs [][]byte
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			certs = append(certs, blk.Bytes)
		}
	}
	if len(certs) < 2 {
		return "", fmt.Errorf("bundle needs CA + client cert (found %d certs)", len(certs))
	}
	caCert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(caCert.Subject.CommonName)
	if name == "" {
		name = strings.TrimSpace(caCert.Subject.String())
	}
	return name, nil
}

func countVisibleChoices(choices []ifaceChoice, filterUp, filterGateway, filterNonVirtual bool) int {
	count := 0
	for _, c := range choices {
		if filterUp && !c.Up {
			continue
		}
		if filterGateway && !c.HasGateway {
			continue
		}
		if filterNonVirtual && (c.Virtual || c.Loopback) {
			continue
		}
		count++
	}
	return count
}

func countVisibleSelected(choices []ifaceChoice, selected map[string]bool, filterUp, filterGateway, filterNonVirtual bool) int {
	count := 0
	for _, c := range choices {
		if filterUp && !c.Up {
			continue
		}
		if filterGateway && !c.HasGateway {
			continue
		}
		if filterNonVirtual && (c.Virtual || c.Loopback) {
			continue
		}
		if selected[c.Name] {
			count++
		}
	}
	return count
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
		Mode:   s.mode,
		PKI:    s.pki,
		Cert:   s.cert,
		Ctrl:   s.ctrl,
		DNS4:   s.dns4,
		DNS6:   s.dns6,
		// Defaults: allow reorder for server->client striping.
		ReorderBufferSize:   128,
		ReorderFlushTimeout: 50 * time.Millisecond,
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
	if verboseLogging {
		if exe, err := os.Executable(); err == nil {
			logFile := filepath.Join(filepath.Dir(exe), "client_debug.log")
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if f != nil {
				// Strip colors/tags if possible, but raw log is fine
				_, _ = fmt.Fprintf(f, "%s %s", time.Now().Format("15:04:05"), msg)
				_ = f.Close()
			}
		}
	}
	appendLog(w.app, w.view, msg)
	return len(p), nil
}

func appendLog(app *tview.Application, view *tview.TextView, msg string) {
	if app == nil || view == nil {
		return
	}
	go func() {
		app.QueueUpdateDraw(func() {
			appendLogSync(view, msg)
		})
	}()
}

func appendLogSync(view *tview.TextView, msg string) {
	if view == nil {
		return
	}
	follow := logViewAtBottom(view)
	_, _ = view.Write([]byte(msg))
	if follow {
		view.ScrollToEnd()
	}
}

func logViewAtBottom(view *tview.TextView) bool {
	if view == nil {
		return true
	}
	row, _ := view.GetScrollOffset()
	if row < 0 {
		return true
	}
	_, _, _, height := view.GetRect()
	if height <= 0 {
		return true
	}
	lineCount := view.GetWrappedLineCount()
	if lineCount == 0 {
		return true
	}
	maxOffset := lineCount - height
	if maxOffset < 0 {
		maxOffset = 0
	}
	return row >= maxOffset
}

func showUsageInUsage(view *tview.TextView, st *tuiState, starting bool) {
	if view == nil || st == nil {
		return
	}
	if starting || st.running != nil {
		return
	}
	lines := []string{"[yellow]Usage[white]"}
	if st.mode == modeBonding {
		lines = append(lines, "Mode: bonding (server-backed)")
	} else {
		lines = append(lines, "Mode: load-balance (local)")
	}

	selected := make([]string, 0)
	for name, on := range st.selected {
		if on {
			selected = append(selected, name)
		}
	}
	sort.Strings(selected)
	if len(selected) == 0 {
		lines = append(lines, "[gray]No interfaces selected.[white]")
	} else {
		lines = append(lines, fmt.Sprintf("Selected interfaces: %d", len(selected)))
		choices := make(map[string]ifaceChoice, len(st.choices))
		for _, c := range st.choices {
			choices[c.Name] = c
		}
		for _, name := range selected {
			c, ok := choices[name]
			if !ok {
				lines = append(lines, fmt.Sprintf("  %s (not found)", name))
				continue
			}
			ip := c.IP
			if ip == "" {
				ip = "-"
			}
			gw := c.Gw
			if gw == "" {
				gw = c.Gw6
			}
			if gw == "" {
				gw = "-"
			}
			ext := externalLabelFor(st, c)
			if ext == "" {
				ext = "-"
			}
			stateLabel := "[red]DOWN[white]"
			if c.Up {
				stateLabel = "[green]UP[white]"
			}
			lines = append(lines, fmt.Sprintf("  %s ip:%s gw:%s ext:%s %s", c.Name, ip, gw, ext, stateLabel))
		}
	}
	lines = append(lines, "[gray]Start to see live stats.[white]")
	view.SetText(strings.Join(lines, "\n"))
}

func appendDiagnosticsLog(details string) {
	if !verboseLogging {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	logFile := filepath.Join(filepath.Dir(exe), "client_debug.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	sep := "-----------"
	_, _ = fmt.Fprintf(f, "\n%s\n%s\n%s\n", sep, details, sep)
}
