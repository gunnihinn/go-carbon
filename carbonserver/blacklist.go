package carbonserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lomik/go-carbon/cache"

	"go.uber.org/zap"
)

var _c *cache.Cache

func InitBlacklistHandler(c *cache.Cache) {
	_c = c
}

func (listener *CarbonserverListener) blacklistHandler(w http.ResponseWriter, r *http.Request) {
	// URL: /_internal/blacklist/?prefix=the.metric.path.with.glob&action=deny

	ctx := r.Context()
	accessLogger := TraceContextToZap(ctx, listener.accessLogger.With(
		zap.String("handler", "find"),
		zap.String("url", r.URL.RequestURI()),
		zap.String("peer", r.RemoteAddr),
	))

	r.ParseForm()
	prefixes := r.Form["prefix"]
	action := r.FormValue("action")

	switch action {
	case "allow":
		_c.AllowPrefixes(prefixes...)
		accessLogger.Info("blacklist",
			zap.String("action", action),
			zap.Strings("prefixes", prefixes),
		)

	case "clear":
		_c.ClearBlacklist()
		accessLogger.Info("blacklist",
			zap.String("action", action),
		)

	case "deny":
		_c.DenyPrefixes(prefixes...)
		accessLogger.Info("blacklist",
			zap.String("action", action),
			zap.Strings("prefixes", prefixes),
		)

	case "help":
		fmt.Fprintf(w, help)
		return
	}

	blacklist := _c.Blacklist()
	blob, err := json.Marshal(blacklist)
	if err != nil {
		http.Error(w, fmt.Sprintf("Couldn't serialize '%v' as JSON: %s", blacklist, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(blob)
}

var help = `/_internal/blacklist?prefix=<prefix>&action=<action>

This internal endpoint controls the metric prefix blacklist. Any data for a
metric that is prefixed by an entry in the blacklist will be dropped.

Actions:

	allow:	Delete the given prefixes from the blacklist.
	clear:	Clear all prefixes from the blacklist.
	deny:	Add the given prefixes to the blacklist.
	help:	Print this message.

Non-help actions will print a JSON representation of the current blacklist
after they have been applied. Empty or invalid input will print the current
blacklist.
`
