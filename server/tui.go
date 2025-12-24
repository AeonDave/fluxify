//go:build linux
// +build linux

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"fluxify/common"
)

// runServerTUI launches the certificate management TUI (mouse-enabled).
// hosts are the SAN entries to use when (re)generating server certs.
func runServerTUI(pki common.PKIPaths, hosts []string, udpPort, ctrlPort int, iface string) {
	app := tview.NewApplication()
	app.EnableMouse(true)

	status := tview.NewTextView().SetDynamicColors(true).SetText("Ready")
	status.SetBorder(true).SetTitle("Status")
	status.SetWrap(true)

	styleBtn := func(b *tview.Button) {
		b.SetBorder(false)
		b.SetBackgroundColor(tcell.ColorDefault)
		b.SetLabelColor(tcell.ColorWhite)
		b.SetLabelColorActivated(tcell.ColorYellow)
	}

	info := tview.NewTextView().SetDynamicColors(true)
	info.SetBorder(true).SetTitle("Server Info")
	info.SetWordWrap(false)
	info.SetWrap(false)

	details := tview.NewTextView().SetDynamicColors(true)
	details.SetBorder(true).SetTitle("Details")
	details.SetWrap(true)

	clientsList := tview.NewList()
	clientsList.ShowSecondaryText(true)
	clientsList.SetBorder(true)
	clientsList.SetTitle("Client certs")

	selectedName := func() string {
		name, _ := clientsList.GetItemText(clientsList.GetCurrentItem())
		return name
	}

	isSelectable := func(name string) bool {
		return name != "" && name != "<no client certs>" && !strings.HasPrefix(name, "<error")
	}

	clientName := ""
	clientInput := tview.NewInputField().SetLabel("New client ").SetFieldWidth(20)
	clientInput.SetChangedFunc(func(text string) { clientName = text })

	pages := tview.NewPages()

	var updateDetailButtons func(string)
	var refreshAndRenderWithButtons func(string)

	generateBtn := tview.NewButton("Generate")
	styleBtn(generateBtn)
	generateBtn.SetSelectedFunc(func() {
		name := strings.TrimSpace(clientName)
		if name == "" {
			setStatus(status, "[yellow]Client name required")
			return
		}
		doGenerate := func() {
			runAsync(app, status, fmt.Sprintf("Generating %s", name), func() error {
				if err := common.EnsureBasePKI(pki, hosts, false); err != nil {
					return err
				}
				datedCert, datedKey, _, _, err := common.GenerateDatedClientCert(pki, name, timeNow())
				if err != nil {
					return err
				}
				if err := removeClientBundles(pki.ClientsDir, clientBaseFromCertPath(datedCert)); err != nil {
					return err
				}
				return writeClientBundle(pki, datedCert, datedKey)
			}, func(err error) {
				if err == nil {
					refreshAndRenderWithButtons(name)
				}
			})
		}
		if clientHasCert(pki, name) {
			confirmOverwrite(pages, fmt.Sprintf("Regenerate client %s? This replaces existing cert.", name), doGenerate)
			return
		}
		doGenerate()
	})

	refreshBtn := tview.NewButton("Refresh")
	styleBtn(refreshBtn)
	refreshBtn.SetSelectedFunc(func() {
		current, _ := clientsList.GetItemText(clientsList.GetCurrentItem())
		refreshAndRenderWithButtons(current)
		app.SetFocus(clientsList)
		setStatus(status, "[green]Refreshed")
	})

	quitBtn := tview.NewButton("Quit")
	styleBtn(quitBtn)
	quitBtn.SetSelectedFunc(func() { app.Stop() })

	regenBtn := tview.NewButton("Regenerate")
	styleBtn(regenBtn)
	regenBtn.SetSelectedFunc(func() {
		modal := tview.NewModal().
			SetText("Regen CA/Server and delete ALL client certs?\nThis is destructive.").
			AddButtons([]string{"Cancel", "Regenerate"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				pages.RemovePage("confirm")
				if buttonLabel != "Regenerate" {
					return
				}
				runAsync(app, status, "Regenerating CA/Server", func() error {
					if err := clearClientCerts(pki.ClientsDir); err != nil {
						return err
					}
					return common.EnsureBasePKI(pki, hosts, true)
				}, func(err error) {
					if err == nil {
						refreshAndRenderWithButtons("")
					}
				})
			})
		pages.AddPage("confirm", modal, true, true)
	})

	regenClientBtn := tview.NewButton("Regenerate client")
	styleBtn(regenClientBtn)
	regenClientBtn.SetSelectedFunc(func() {
		name := selectedName()
		if !isSelectable(name) {
			return
		}
		confirmOverwrite(pages, fmt.Sprintf("Regenerate client %s? This replaces existing cert.", name), func() {
			runAsync(app, status, fmt.Sprintf("Regenerating %s", name), func() error {
				return regenerateClientCert(pki, name)
			}, func(err error) {
				if err == nil {
					refreshAndRenderWithButtons(name)
				}
			})
		})
	})

	deleteClientBtn := tview.NewButton("Delete client")
	styleBtn(deleteClientBtn)
	deleteClientBtn.SetSelectedFunc(func() {
		name := selectedName()
		if !isSelectable(name) {
			return
		}
		confirmOverwrite(pages, fmt.Sprintf("Delete client %s certs? This removes files from disk.", name), func() {
			runAsync(app, status, fmt.Sprintf("Deleting %s", name), func() error {
				return deleteClientCerts(pki, name)
			}, func(err error) {
				if err == nil {
					refreshAndRenderWithButtons("")
				}
			})
		})
	})

	updateDetailButtons = func(name string) {
		disable := !isSelectable(name)
		regenClientBtn.SetDisabled(disable)
		deleteClientBtn.SetDisabled(disable)
	}

	refreshAndRenderWithButtons = func(preferred string) {
		refreshAndRender(clientsList, details, pki, preferred)
		updateDetailButtons(selectedName())
	}

	detailButtons := tview.NewFlex().SetDirection(tview.FlexColumn)
	detailButtons.SetBorder(true).SetTitle("Client Actions")
	detailButtons.AddItem(regenClientBtn, 0, 1, false)
	detailButtons.AddItem(deleteClientBtn, 0, 1, false)

	detailPane := tview.NewFlex().SetDirection(tview.FlexRow)
	detailPane.AddItem(details, 0, 3, false)
	detailPane.AddItem(detailButtons, 5, 0, false)

	clientsList.SetMouseCapture(func(action tview.MouseAction, ev *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		x, y := ev.Position()
		lx, ly, lw, lh := clientsList.GetRect()
		inside := x >= lx && x < lx+lw && y >= ly && y < ly+lh
		if inside {
			row := y - ly - 1
			if row >= 0 && row < clientsList.GetItemCount() {
				clientsList.SetCurrentItem(row)
			}
			app.SetFocus(clientsList)
		}
		return action, ev
	})

	actions := tview.NewGrid().SetRows(1, 1, 1, 1, 1, 1).SetColumns(2, 35, 2, 14, 2)
	actions.SetBorder(true).SetTitle("Actions")
	actions.AddItem(tview.NewTextView().SetText("Regen CA/Server"), 0, 1, 1, 1, 0, 0, false)
	actions.AddItem(regenBtn, 0, 3, 1, 1, 0, 0, false)
	actions.AddItem(clientInput, 1, 1, 1, 1, 0, 0, true)
	actions.AddItem(generateBtn, 1, 3, 1, 1, 0, 0, false)
	actions.AddItem(tview.NewBox(), 2, 0, 1, 5, 0, 0, false)
	actions.AddItem(tview.NewTextView().SetText("Refresh"), 3, 1, 1, 1, 0, 0, false)
	actions.AddItem(refreshBtn, 3, 3, 1, 1, 0, 0, false)
	actions.AddItem(tview.NewTextView().SetText("Quit"), 4, 1, 1, 1, 0, 0, false)
	actions.AddItem(quitBtn, 4, 3, 1, 1, 0, 0, false)
	actions.AddItem(tview.NewBox(), 5, 0, 1, 5, 0, 0, false)

	setInfo(info, pki, hosts, udpPort, ctrlPort, iface)
	refreshAndRenderWithButtons("")

	clientsList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		selectAndRender(clientsList, details, pki)
		updateDetailButtons(selectedName())
	})

	top := tview.NewFlex().SetDirection(tview.FlexColumn)
	top.AddItem(actions, 0, 1, true)
	top.AddItem(status, 0, 1, false)

	rowLists := tview.NewFlex().SetDirection(tview.FlexColumn)
	rowLists.AddItem(clientsList, 0, 1, true)
	rowLists.AddItem(detailPane, 0, 1, false)

	main := tview.NewFlex().SetDirection(tview.FlexRow)
	main.AddItem(top, 8, 0, true)
	main.AddItem(rowLists, 0, 2, false)
	main.AddItem(info, 11, 0, false)

	main.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			app.Stop()
			return nil
		}
		return event
	})

	pages.AddPage("main", main, true, true)
	app.SetFocus(clientsList)

	if err := app.SetRoot(pages, true).Run(); err != nil {
		log.Fatalf("tui error: %v", err)
	}
}

func setInfo(tv *tview.TextView, pki common.PKIPaths, hosts []string, udpPort, ctrlPort int, iface string) {
	sanDNS, sanIPs := serverCertSANs(pki.ServerCert)
	ifaceLabel := iface
	if ifaceLabel == "" {
		ifaceLabel = "(default)"
	}
	hostList := "-"
	if len(hosts) > 0 {
		hostList = strings.Join(hosts, ", ")
	}
	text := fmt.Sprintf("[yellow]Server Ports[white]\nUDP data: [white]%d\nTLS control: [white]%d\n[yellow]Bind[white]\nInterface: [white]%s\n[yellow]Server Cert SAN[white]\nDNS: [white]%s\nIP: [white]%s\n[yellow]Configured Hosts[white]\n%s\n[yellow]PKI Paths[white]\nCA: [white]%s\nCA Key: [white]%s\nServer Cert: [white]%s\nServer Key: [white]%s\nClients dir: [white]%s",
		udpPort, ctrlPort, ifaceLabel, sanDNS, sanIPs, hostList, pki.CACert, pki.CAKey, pki.ServerCert, pki.ServerKey, pki.ClientsDir)
	tv.SetText(text)
}

func serverCertSANs(certPath string) (string, string) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "-", "-"
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "-", "-"
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "-", "-"
	}
	return formatCertSANs(crt)
}

func setStatus(tv *tview.TextView, msg string) {
	tv.SetText(msg)
}

func updateDetails(tv *tview.TextView, msg string) {
	tv.SetText(msg)
}

func refreshClients(list *tview.List, pki common.PKIPaths) int {
	_ = os.MkdirAll(pki.ClientsDir, 0o700)
	list.Clear()
	entries, err := listClientCerts(pki)
	if err != nil {
		list.AddItem(fmt.Sprintf("<error: %v>", err), "", 0, nil)
		return 0
	}
	for _, e := range entries {
		list.AddItem(e.name, e.warn, 0, nil)
	}
	if len(entries) == 0 {
		list.AddItem("<no client certs>", "", 0, nil)
	}
	return len(entries)
}

func refreshAndRender(list *tview.List, details *tview.TextView, pki common.PKIPaths, preferred string) {
	count := refreshClients(list, pki)
	if preferred != "" {
		selectByName(list, preferred)
	} else if count > 0 {
		list.SetCurrentItem(0)
	}
	selectAndRender(list, details, pki)
}

func selectAndRender(list *tview.List, details *tview.TextView, pki common.PKIPaths) {
	idx := list.GetCurrentItem()
	main, _ := list.GetItemText(idx)
	if main == "" || main == "<no client certs>" {
		updateDetails(details, "<no details>")
		return
	}
	var body string
	if txt, err := renderCertDetails(pki, main); err == nil {
		body = txt
	} else {
		if alt, altErr := renderAnyCertDetails(pki, main); altErr == nil {
			body = alt
		} else {
			body = fmt.Sprintf("[red]%v", err)
		}
	}
	updateDetails(details, body)
}

type clientEntry struct {
	name string
	warn string
}

func listClientCerts(pki common.PKIPaths) ([]clientEntry, error) {
	entries := make([]clientEntry, 0)
	seen := make(map[string]struct{})
	err := filepath.WalkDir(pki.ClientsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d == nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, "-key.pem") {
			return nil
		}
		if !strings.HasSuffix(name, ".pem") {
			return nil
		}
		base := ""
		if m := datedCertRe.FindStringSubmatch(name); len(m) == 2 {
			base = m[1]
		} else {
			base = strings.TrimSuffix(name, ".pem")
		}
		seen[base] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		warn := ""
		certPath, keyPath, err := common.FindLatestDatedClientCert(pki, name)
		if err == nil {
			if _, err := os.Stat(certPath); err != nil {
				warn = fmt.Sprintf("cert missing: %v", err)
			}
			if _, err := os.Stat(keyPath); err != nil {
				if warn != "" {
					warn += "; "
				}
				warn += fmt.Sprintf("key missing: %v", err)
			}
		}
		entries = append(entries, clientEntry{name: name, warn: warn})
	}
	return entries, nil
}

// clientCertPair resolves latest cert/key for a client name.
func clientCertPair(pki common.PKIPaths, name string) (cert, key string, err error) {
	return common.FindLatestDatedClientCert(pki, name)
}

// renderCertDetails loads certificate info for display.
func renderCertDetails(pki common.PKIPaths, name string) (string, error) {
	certPath, _, err := clientCertPair(pki, name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	bl, _ := pem.Decode(b)
	if bl == nil {
		return "", fmt.Errorf("invalid pem")
	}
	crt, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return "", err
	}
	gen := crt.NotBefore.UTC().Format(time.RFC3339)
	exp := crt.NotAfter.UTC().Format(time.RFC3339)
	subject := crt.Subject.CommonName
	sanDNS, sanIPs := formatCertSANs(crt)
	return fmt.Sprintf("Client: [white]%s\nCN: [white]%s\nGenerated: [white]%s\nExpires: [white]%s\nIssuer: [white]%s\nSAN DNS: [white]%s\nSAN IP: [white]%s", name, subject, gen, exp, crt.Issuer.CommonName, sanDNS, sanIPs), nil
}

// renderAnyCertDetails tries any cert on disk for the client (non-dated fallback) to aid debugging.
func renderAnyCertDetails(pki common.PKIPaths, name string) (string, error) {
	pattern := filepath.Join(pki.ClientsDir, fmt.Sprintf("%s*.pem", name))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	for _, certPath := range matches {
		if strings.HasSuffix(certPath, "-key.pem") {
			continue
		}
		b, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		bl, _ := pem.Decode(b)
		if bl == nil {
			continue
		}
		crt, err := x509.ParseCertificate(bl.Bytes)
		if err != nil {
			continue
		}
		gen := crt.NotBefore.UTC().Format(time.RFC3339)
		exp := crt.NotAfter.UTC().Format(time.RFC3339)
		sanDNS, sanIPs := formatCertSANs(crt)
		return fmt.Sprintf("Client: [white]%s\nCN: [white]%s\nGenerated: [white]%s\nExpires: [white]%s\nIssuer: [white]%s\nSAN DNS: [white]%s\nSAN IP: [white]%s\n[gray](from %s)", name, crt.Subject.CommonName, gen, exp, crt.Issuer.CommonName, sanDNS, sanIPs, filepath.Base(certPath)), nil
	}
	return "", fmt.Errorf("no parsable cert for %s", name)
}

func formatCertSANs(crt *x509.Certificate) (string, string) {
	dns := "-"
	if len(crt.DNSNames) > 0 {
		dns = strings.Join(crt.DNSNames, ", ")
	}
	ips := "-"
	if len(crt.IPAddresses) > 0 {
		ipParts := make([]string, 0, len(crt.IPAddresses))
		for _, ip := range crt.IPAddresses {
			ipParts = append(ipParts, ip.String())
		}
		ips = strings.Join(ipParts, ", ")
	}
	return dns, ips
}

// clearClientCerts removes all files in the clients directory.
func clearClientCerts(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

var datedCertRe = regexp.MustCompile(`^(.+)-\d{8}-\d{6}\.pem$`)

// timeNow allows tests to stub time.
var timeNow = func() time.Time {
	return time.Now()
}

// runAsync executes work in a goroutine and updates the status with a spinner until completion.
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

func regenerateClientCert(pki common.PKIPaths, name string) error {
	datedCert, datedKey, _, _, err := common.GenerateDatedClientCert(pki, name, timeNow())
	if err != nil {
		return err
	}
	if err := removeClientBundles(pki.ClientsDir, clientBaseFromCertPath(datedCert)); err != nil {
		return err
	}
	return writeClientBundle(pki, datedCert, datedKey)
}

func deleteClientCerts(pki common.PKIPaths, name string) error {
	matches, err := filepath.Glob(filepath.Join(pki.ClientsDir, fmt.Sprintf("%s-*.pem", name)))
	if err != nil {
		return err
	}
	for _, m := range matches {
		_ = os.Remove(m)
		_ = os.Remove(strings.TrimSuffix(m, ".pem") + "-key.pem")
	}
	if err := removeClientBundles(pki.ClientsDir, name); err != nil {
		return err
	}
	return nil
}

func clientHasCert(pki common.PKIPaths, name string) bool {
	pattern := filepath.Join(pki.ClientsDir, fmt.Sprintf("%s-*.pem", name))
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		if strings.HasSuffix(m, "-key.pem") {
			continue
		}
		key := strings.TrimSuffix(m, ".pem") + "-key.pem"
		if _, err := os.Stat(key); err == nil {
			return true
		}
	}
	_, _, err := common.FindLatestDatedClientCert(pki, name)
	return err == nil
}

func selectByName(list *tview.List, name string) {
	for i := 0; i < list.GetItemCount(); i++ {
		main, _ := list.GetItemText(i)
		if main == name {
			list.SetCurrentItem(i)
			return
		}
	}
}

func confirmOverwrite(pages *tview.Pages, text string, onConfirm func()) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"Cancel", "Confirm"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			pages.RemovePage("confirmOverwrite")
			if buttonLabel == "Confirm" {
				onConfirm()
			}
		})
	pages.AddPage("confirmOverwrite", modal, true, true)
}

func writeClientBundle(pki common.PKIPaths, certPath, keyPath string) error {
	read := func(src string) ([]byte, error) {
		b, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	caBytes, err := read(pki.CACert)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	certBytes, err := read(certPath)
	if err != nil {
		return err
	}
	keyBytes, err := read(keyPath)
	if err != nil {
		return err
	}
	payload := make([]byte, 0, len(caBytes)+len(certBytes)+len(keyBytes)+2)
	payload = append(payload, caBytes...)
	payload = append(payload, '\n')
	payload = append(payload, certBytes...)
	payload = append(payload, '\n')
	payload = append(payload, keyBytes...)
	bundlePath := strings.TrimSuffix(certPath, ".pem") + ".bundle"
	return os.WriteFile(bundlePath, payload, 0o600)
}

func clientBaseFromCertPath(certPath string) string {
	base := filepath.Base(certPath)
	if m := datedCertRe.FindStringSubmatch(base); len(m) == 2 {
		return m[1]
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func removeClientBundles(dir, name string) error {
	if name == "" {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, fmt.Sprintf("%s-*.bundle", name)))
	if err != nil {
		return err
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
	_ = os.Remove(filepath.Join(dir, fmt.Sprintf("%s.bundle", name)))
	return nil
}
