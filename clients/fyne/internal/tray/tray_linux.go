//go:build linux

package tray

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

// ProbeTimeout bounds the whole session-bus exchange. Generous for two round
// trips on a local socket, and short enough that a wedged bus costs a moment at
// startup rather than a window that never appears — this runs before the first
// frame is drawn.
const ProbeTimeout = 2 * time.Second

const (
	watcherName      = "org.kde.StatusNotifierWatcher"
	watcherPath      = "/StatusNotifierWatcher"
	watcherHostProp  = watcherName + ".IsStatusNotifierHostRegistered"
	propertiesGet    = "org.freedesktop.DBus.Properties.Get"
	busNameHasOwner  = "org.freedesktop.DBus.NameHasOwner"
	sessionBusEnvVar = "DBUS_SESSION_BUS_ADDRESS"
)

func available() bool { return decide(hostRegistered) }

// decide turns the probe's three outcomes into the client's two.
//
// Any error is NO, and that is the safe direction rather than the pessimistic
// one: a false no leaves the client behaving exactly as it did before #186,
// which is a known state somebody can live with, while a false yes hides the
// window into a machine with nothing to get it back from.
//
// Split out from the bus call so the decision is testable without a session
// bus — a test host has none, which would otherwise make this the one piece of
// #186 that only ever runs on a developer's desktop.
func decide(ask func(context.Context) (bool, error)) bool {
	ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
	defer cancel()
	ok, err := ask(ctx)
	return err == nil && ok
}

// hostRegistered asks the session bus whether a StatusNotifierItem host is
// attached to the watcher.
//
// Two questions rather than one, because the watcher and the host are separate
// things and only the second draws anything. A bus with a watcher on it and no
// host — which is what a panel that has been removed but whose service file is
// still installed leaves behind — would answer the first question yes and show
// no icon.
//
// The address is read from the environment rather than obtained through
// dbus.ConnectSessionBus, which AUTOLAUNCHES a daemon when there is none. A
// probe that starts a background service as a side effect of asking a question
// is the wrong shape anywhere; on a machine with no session bus it would also
// be answering "is there a tray" by creating infrastructure.
func hostRegistered(ctx context.Context) (bool, error) {
	addr := os.Getenv(sessionBusEnvVar)
	if addr == "" {
		return false, errors.New("no session bus")
	}
	conn, err := dbus.Connect(addr, dbus.WithContext(ctx))
	if err != nil {
		return false, err
	}
	defer conn.Close()

	var owned bool
	if err := conn.BusObject().CallWithContext(ctx, busNameHasOwner, 0, watcherName).Store(&owned); err != nil {
		return false, err
	}
	if !owned {
		return false, nil
	}

	// Properties.Get rather than BusObject.GetProperty: the latter takes no
	// context, so a watcher that accepts the connection and never answers would
	// hang startup with no bound at all.
	var v dbus.Variant
	obj := conn.Object(watcherName, dbus.ObjectPath(watcherPath))
	if err := obj.CallWithContext(ctx, propertiesGet, 0, watcherName, "IsStatusNotifierHostRegistered").Store(&v); err != nil {
		return false, err
	}
	registered, ok := v.Value().(bool)
	if !ok {
		return false, errors.New(watcherHostProp + " is not a boolean")
	}
	return registered, nil
}
