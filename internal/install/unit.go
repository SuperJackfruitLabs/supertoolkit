package install

import (
	"fmt"
	"strings"
)

// group is the service's primary group: the named one, else the user's own.
func (p Plan) group() string {
	if p.Group != "" {
		return p.Group
	}
	return p.User
}

// socketMode is 0660 only when a group is named, so the agent's group can
// reach the socket at the filesystem layer. The uid allowlist on ExecStart
// stays the authorisation.
func (p Plan) socketMode() string {
	if p.Group != "" {
		return "0660"
	}
	return "0600"
}

func (p Plan) runtimeMode() string {
	if p.Group != "" {
		return "0750"
	}
	return "0700"
}

// Unit renders the systemd service. It names no secret: the passphrase comes
// from the service manager's credential store via LoadCredential, which stk
// reads at $CREDENTIALS_DIRECTORY/stk-passphrase.
func Unit(p Plan) string {
	var exec strings.Builder
	fmt.Fprintf(&exec, "%s serve --proxy-listen 127.0.0.1:%d --socket-mode %s", p.Binary, p.ProxyPort, p.socketMode())
	for _, uid := range p.AgentUIDs {
		fmt.Fprintf(&exec, " --allow-uid %d", uid)
	}
	// /run is a tmpfs: without RuntimeDirectory= the directory (and its group
	// mode) is gone after a reboot and the daemon would recreate it 0700.
	runtime := ""
	if rest, ok := strings.CutPrefix(p.RuntimeDir, "/run/"); ok && rest != "" && !strings.Contains(rest, "/") {
		runtime = fmt.Sprintf("RuntimeDirectory=%s\nRuntimeDirectoryMode=%s\nRuntimeDirectoryPreserve=yes\n", rest, p.runtimeMode())
	}
	desc := "supertoolkit credential broker"
	if p.unitName() != DefaultUnitName {
		desc += " (" + p.unitName() + ")"
	}
	return fmt.Sprintf(`[Unit]
Description=%[8]s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[1]s
Group=%[2]s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=%[3]s %[4]s
UMask=0077
%[7]sLoadCredential=stk-passphrase:%[3]s/stk-passphrase.key
Environment=STK_HOME=%[3]s STK_CONFIG=%[5]s STK_SOCKET=%[4]s/stk.sock
ExecStart=%[6]s
Restart=on-failure

[Install]
WantedBy=multi-user.target
`, p.User, p.group(), p.StateDir, p.RuntimeDir, p.ConfigPath, exec.String(), runtime, desc)
}
