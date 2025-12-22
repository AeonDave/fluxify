package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

	info := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true).SetWrap(true)
	info.SetBorder(true).SetTitle("Info & Usage")
	log.SetOutput(&tuiLogWriter{app: app, view: info})

	statusBar := tview.NewTextView().SetDynamicColors(true)
	statusBar.SetBorder(true).SetTitle("Status")

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
	refreshBtn := tview.NewButton(" REFRESH IFs ")
	styleActionBtn(refreshBtn, tcell.ColorDarkBlue)
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

	filterUpBox := tview.NewCheckbox().SetLabel("Up").SetChecked(true)
	filterGatewayBox := tview.NewCheckbox().SetLabel("Gateway").SetChecked(true)
	filterNonVirtualBox := tview.NewCheckbox().SetLabel("Non-virtual").SetChecked(true)
	filtersRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	filtersRow.AddItem(filterUpBox, 0, 1, false)
	filtersRow.AddItem(filterGatewayBox, 0, 1, false)
	filtersRow.AddItem(filterNonVirtualBox, 0, 1, false)
	configBox.AddItem(filtersRow, 1, 0, false)

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
	form.AddItem(topRow, 11, 0, false)
	form.AddItem(statusBar, 2, 0, false)
	form.AddItem(ifaceList, 0, 1, true)
	form.AddItem(info, 10, 0, false)
	form.AddItem(actionStatus, 3, 0, false)

	app.SetRoot(form, true).SetFocus(ifaceList)

	// Populate interfaces
	var refreshIfaces func()
	var redrawList func()
	var updateButtons func()
	var updateStatus func()
	var persistConfig func()
	var start func()
	var scanInFlight bool

	serverFieldDisabled := false
	suppressServerChange := false
	var starting bool // prevent multiple concurrent starts and preserve info panel

	persistConfig = func() {
		if starting || state.running != nil {
			return
		}
		cfg := state.buildConfig()
		saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Cert: cfg.Cert, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
	}

	redrawList = func() {
		ifaceList.Clear()
		for _, c := range state.choices {
			if filterUp && !c.Up {
				continue
			}
			if filterGateway && !c.HasGateway {
				continue
			}
			if filterNonVirtual && (c.Virtual || c.Loopback) {
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
				state.selected[c.Name] = false
				availTag = "[red]NO[white]"
			}
			line := fmt.Sprintf("%s %s %s", selTag, availTag, label)
			choice := c
			ifaceList.AddItem(line, "", 0, func() {
				// Block toggles while running
				if starting || state.running != nil {
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
		// Do not allow modifying interface list while starting or running
		if starting || state.running != nil {
			actionStatus.SetText("[yellow]Running: stop before changing interfaces")
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
				queueExternalIPChecks(app, state, choices, redrawList, updateButtons)
				actionStatus.SetText("Idle")
				scanInFlight = false
			})
		}()
	}

	refreshBtn.SetSelectedFunc(func() {
		if starting || state.running != nil {
			actionStatus.SetText("[yellow]Running: stop before changing interfaces")
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
		app.QueueUpdateDraw(func() {
			actionStatus.SetText(msg)
		})
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
		visibleCount := countVisibleChoices(state.choices, filterUp, filterGateway, filterNonVirtual)
		visibleSelected := countVisibleSelected(state.choices, state.selected, filterUp, filterGateway, filterNonVirtual)
		stateLabel := "IDLE"
		stateColor := "[white]"
		if starting {
			stateLabel = "STARTING"
			stateColor = "[yellow]"
		} else if state.running != nil {
			stateLabel = "RUNNING"
			stateColor = "[green]"
		}
		msg := fmt.Sprintf("Mode: %s | Server: %s | IFs: %d selected (%d/%d shown) | State: %s%s[white]",
			state.mode, srv, selected, visibleSelected, visibleCount, stateColor, stateLabel)

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
		filterLine := fmt.Sprintf("Filters: up=%s gw=%s non-virtual=%s", onOff(filterUp), onOff(filterGateway), onOff(filterNonVirtual))
		if len(needs) > 0 {
			filterLine += " | Need: " + strings.Join(needs, ", ")
		}

		setStatusBarDirect(msg + "\n" + filterLine)
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
			setActionStatus("[red]Select server and at least 2 interfaces (server only needed for bonding)")
			starting = false
			return
		}
		if state.mode == modeBonding {
			path, err := detectClientBundlePath(state.pki)
			if err != nil {
				setActionStatus(fmt.Sprintf("[red]%v", err))
				return
			}
			state.cert = path
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
		runAsync(app, actionStatus, "Starting", func() error {
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
			_, _ = fmt.Fprintf(info, "[green]Started %s with %d interfaces.[white]\n", cfg.Mode, len(cfg.Ifaces))
			saveStoredConfig(storedConfig{Server: cfg.Server, Mode: cfg.Mode, Ifaces: cfg.Ifaces, Cert: cfg.Cert, PKI: cfg.PKI, Ctrl: cfg.Ctrl})
			stopBtn.SetDisabled(false)
		})
	}

	stop := func() {
		if state.running != nil {
			stopBtn.SetDisabled(true)
			runAsync(app, actionStatus, "Stopping", func() error {
				state.running()
				state.running = nil
				return nil
			}, func(err error) {
				startBtn.SetDisabled(!state.canStart())
				// Allow interface changes again
				refreshBtn.SetDisabled(false)
				showUsageInInfo(info, state.mode)
				_, _ = fmt.Fprintln(info, "[green]Stopped.[white]")
				updateButtons()
			})
			return
		}
		startBtn.SetDisabled(!state.canStart())
		stopBtn.SetDisabled(true)
		refreshBtn.SetDisabled(false)
		setActionStatus("[yellow]stopped")
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
	cert     string
	pki      string
	ctrl     int
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
	log.Printf("scanInterfaces: starting")
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
			log.Printf("scanInterfaces: checking %s", iface.Name)
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
	log.Printf("scanInterfaces: found %d candidates", len(choices))
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
					log.Printf("external ip (%s): %v", name, err)
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
	defer resp.Body.Close()
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

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
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
