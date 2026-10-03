package oauth

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
)

// loginData is the login and consent page. Script is a constant (see
// passkeyLoginJS); passing it as data keeps html/template from having to
// parse JavaScript source in the template text. ClientHost is the host of a
// client metadata document's URL (CIMD clients only): like RedirectHost it
// is something the owner can check, unlike ClientName, which the client
// chose itself.
type loginData struct {
	Nonce, ClientName, RedirectHost, ClientHost, ID, CSRF, Error string
	Passkey                                                      bool
	Script                                                       template.JS
}

type messageData struct{ Nonce, Title, Message string }

func newNonce() string { return base64.StdEncoding.EncodeToString(randBytes(16)) }

func originOf(u *url.URL) string {
	if u == nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// pageHeaders replaces the CSP from secureHeaders with one that allows only
// this response's nonce. form-action includes the client's origin because
// browsers apply it to the redirect chain after a form post (login, then
// /authorize/callback, then the client's redirect URI). Cache-Control,
// Referrer-Policy, and X-Frame-Options come from secureHeaders.
func pageHeaders(w http.ResponseWriter, nonce, formTarget string) {
	formAction := "'self'"
	if formTarget != "" {
		formAction += " " + formTarget
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; form-action %s; frame-ancestors 'none'; base-uri 'none'",
		nonce, nonce, formAction))
}

func renderLogin(w http.ResponseWriter, status int, d loginData, formTarget string) {
	d.Nonce = newNonce()
	d.Script = passkeyLoginJS
	pageHeaders(w, d.Nonce, formTarget)
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, d)
}

func renderMessage(w http.ResponseWriter, status int, title, msg string) {
	d := messageData{Nonce: newNonce(), Title: title, Message: msg}
	pageHeaders(w, d.Nonce, "")
	w.WriteHeader(status)
	_ = messageTmpl.Execute(w, d)
}

const pageStyle = `body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#1b1b1b;background:#fff}` +
	`button,input{font-size:1rem;padding:.5rem .75rem}input{width:14rem}.err{color:#b00020}.muted{color:#555}code{word-break:break-all}form{margin:1rem 0}` +
	`dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem}dt{color:#555}dd{margin:0;word-break:break-all}`

var messageTmpl = template.Must(template.New("message").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title><style nonce="{{.Nonce}}">` + pageStyle + `</style></head>
<body><h1>{{.Title}}</h1><p>{{.Message}}</p></body></html>`))

// The name, the redirect host, and the publisher host are shown with the
// same weight: the name is whatever the client registered, so the hosts are
// what the owner should check.
var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approve a connection to your vault</title><style nonce="{{.Nonce}}">` + pageStyle + `</style></head>
<body>
<h1>Connect an assistant</h1>
<p>An assistant wants to read and write the notes in this vault.</p>
<dl>
<dt>Name (chosen by the client)</dt><dd><strong>{{.ClientName}}</strong></dd>
<dt>Returns to</dt><dd><strong>{{.RedirectHost}}</strong></dd>
{{if .ClientHost}}<dt>Published by</dt><dd><strong>{{.ClientHost}}</strong></dd>{{end}}
</dl>
<p class="muted">Approve only if you started this connection yourself, just now, and you recognize these hosts.</p>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Passkey}}<p><button id="passkey" type="button" data-id="{{.ID}}" data-csrf="{{.CSRF}}">Approve with passkey</button></p>
<p class="err" id="pkerr" role="alert"></p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="id" value="{{.ID}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label>Authenticator code or recovery code<br><input name="code" autocomplete="one-time-code" maxlength="32" required autofocus></label></p>
<button type="submit">Approve with code</button>
</form>
<form method="post" action="/login/deny">
<input type="hidden" name="id" value="{{.ID}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Deny</button>
</form>
{{if .Passkey}}<script nonce="{{.Nonce}}">{{.Script}}</script>{{end}}
</body></html>`))

// passkeyLoginJS runs a discoverable WebAuthn login: get options from
// /login/passkey/begin, call the authenticator, post the assertion to
// /login/passkey/finish, follow the returned redirect. It encodes binary
// fields by hand (base64url) instead of relying on
// PublicKeyCredential.parseRequestOptionsFromJSON, which older browsers lack.
// #nosec G101 -- browser script that names navigator.credentials; it holds no secret
const passkeyLoginJS template.JS = `(function () {
  var btn = document.getElementById('passkey');
  function dec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); });
  }
  function enc(buf) {
    var b = '', a = new Uint8Array(buf);
    for (var i = 0; i < a.length; i++) { b += String.fromCharCode(a[i]); }
    return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  btn.addEventListener('click', async function () {
    var q = new URLSearchParams({id: btn.dataset.id, csrf: btn.dataset.csrf}).toString();
    try {
      var r = await fetch('/login/passkey/begin?' + q, {method: 'POST'});
      if (!r.ok) { throw new Error('begin'); }
      var pk = (await r.json()).publicKey;
      pk.challenge = dec(pk.challenge);
      (pk.allowCredentials || []).forEach(function (c) { c.id = dec(c.id); });
      var c = await navigator.credentials.get({publicKey: pk});
      var body = JSON.stringify({id: c.id, rawId: enc(c.rawId), type: c.type, response: {
        clientDataJSON: enc(c.response.clientDataJSON),
        authenticatorData: enc(c.response.authenticatorData),
        signature: enc(c.response.signature),
        userHandle: c.response.userHandle ? enc(c.response.userHandle) : undefined}});
      var f = await fetch('/login/passkey/finish?' + q, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: body});
      if (!f.ok) { throw new Error('finish'); }
      location.assign((await f.json()).redirect);
    } catch (e) {
      document.getElementById('pkerr').textContent = 'Passkey sign-in did not work. Try again or use a code.';
    }
  });
})();`
