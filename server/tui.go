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
func runServerTUI(pki common.PKIPaths, hosts []string, udpPort, ctrlPort int, iface string, verbose bool) {
	app := tview.NewApplication()
	app.EnableMouse(true)

	mouseEnabled := true

	status := tview.NewTextView().SetDynamicColors(true).SetText("Ready")
	status.SetBorder(true).SetTitle("Status (F2: toggle mouse)")
	status.SetWrap(true)

	setMouseEnabled := func(enabled bool) {
		mouseEnabled = enabled
		app.EnableMouse(enabled)
		if enabled {
			setStatus(status, "Ready (mouse enabled)")
		} else {
			setStatus(status, "Ready (mouse disabled - you can now select/copy text)")
		}
	}

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
				_, err := common.GenerateClientBundle(pki, name)
				return err
			}, func(err error) {
				if err == nil {
					refreshAndRenderWithButtons(name)
				}
			})
		}
		if clientHasBundle(pki, name) {
			confirmOverwrite(pages, fmt.Sprintf("Regenerate client %s? This replaces existing bundle.", name), doGenerate)
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
					if err := clearClientBundles(pki.ClientsDir); err != nil {
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
		confirmOverwrite(pages, fmt.Sprintf("Regenerate client %s? This replaces existing bundle.", name), func() {
			runAsync(app, status, fmt.Sprintf("Regenerating %s", name), func() error {
				_, err := common.GenerateClientBundle(pki, name)
				return err
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
		confirmOverwrite(pages, fmt.Sprintf("Delete client %s bundle? This removes files from disk.", name), func() {
			runAsync(app, status, fmt.Sprintf("Deleting %s", name), func() error {
				return deleteClientBundle(pki, name)
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
		if event.Key() == tcell.KeyF2 {
			setMouseEnabled(!mouseEnabled)
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

func setStatus(tv *tview.TextView, msg string)     { tv.SetText(msg) }
func updateDetails(tv *tview.TextView, msg string) { tv.SetText(msg) }

func refreshClients(list *tview.List, pki common.PKIPaths) int {
	_ = os.MkdirAll(pki.ClientsDir, 0o700)
	list.Clear()
	entries, err := listClientBundles(pki)
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
	if txt, err := renderBundleDetails(pki, main); err == nil {
		updateDetails(details, txt)
		return
	}
	updateDetails(details, "[red]failed to parse bundle")
}

type clientEntry struct {
	name string
	warn string
}

func listClientBundles(pki common.PKIPaths) ([]clientEntry, error) {
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
		if !strings.HasSuffix(name, ".bundle") {
			return nil
		}
		base := strings.TrimSuffix(name, ".bundle")
		// remove possible date suffix (legacy)
		if m := datedBundleRe.FindStringSubmatch(base); len(m) == 2 {
			base = m[1]
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
		// We expect <name>.bundle
		p := filepath.Join(pki.ClientsDir, name+".bundle")
		if _, err := os.Stat(p); err != nil {
			warn = fmt.Sprintf("missing: %v", err)
		}
		entries = append(entries, clientEntry{name: name, warn: warn})
	}
	return entries, nil
}

func renderBundleDetails(pki common.PKIPaths, name string) (string, error) {
	p := filepath.Join(pki.ClientsDir, name+".bundle")
	// Bundle is gzip+PEM, use loader to validate and obtain cert chain.
	tlsCfg, err := common.LoadClientBundle(p)
	if err != nil {
		return "", err
	}
	if len(tlsCfg.Certificates) == 0 || len(tlsCfg.Certificates[0].Certificate) == 0 {
		return "", fmt.Errorf("bundle has no certificate")
	}
	crt, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		return "", err
	}
	gen := crt.NotBefore.UTC().Format(time.RFC3339)
	exp := crt.NotAfter.UTC().Format(time.RFC3339)
	sanDNS, sanIPs := formatCertSANs(crt)
	return fmt.Sprintf("Client: [white]%s\nCN: [white]%s\nGenerated: [white]%s\nExpires: [white]%s\nIssuer: [white]%s\nSAN DNS: [white]%s\nSAN IP: [white]%s",
		name, crt.Subject.CommonName, gen, exp, crt.Issuer.CommonName, sanDNS, sanIPs), nil
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

func clearClientBundles(dir string) error {
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

var datedBundleRe = regexp.MustCompile(`^(.+)-\d{8}-\d{6}$`)

var timeNow = func() time.Time { return time.Now() }

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

func clientHasBundle(pki common.PKIPaths, name string) bool {
	_, err := os.Stat(filepath.Join(pki.ClientsDir, name+".bundle"))
	return err == nil
}

func deleteClientBundle(pki common.PKIPaths, name string) error {
	_ = os.Remove(filepath.Join(pki.ClientsDir, name+".bundle"))
	return nil
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
