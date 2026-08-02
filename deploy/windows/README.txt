Bacchus for Windows -- portable bundle {{VERSION}}
=================================================

This folder is the whole program. Nothing was installed, nothing was written
to the registry, and there is nothing to uninstall: to remove Bacchus, delete
this folder. It runs from a USB stick.


WHAT IS IN THIS FOLDER

  bacchus-fyne.exe           The client.

  wintun.dll                 The tunnel driver the client loads to create its
                             network adapter. The client cannot connect
                             without it. Version {{WINTUN_VERSION}}, copied
                             here exactly as published on wintun.net.

  LICENSE.wintun.txt         wintun's own licence. wintun is (c) WireGuard LLC
                             and is not part of Bacchus; it is redistributed
                             unmodified, which is what its licence allows.

  bacchus-fyne.config.json   Your settings. You have to edit this before the
                             first connection -- see SETTING IT UP below.

  README.txt                 This file.

Keep the five files together in one folder. The client looks for wintun.dll
and for its config file next to itself.


BEFORE YOU START

1. RUN IT AS ADMINISTRATOR. Creating the tunnel adapter and changing this
   machine's routes both require it. Windows should ask for permission when
   you start the program; if it does not, right-click bacchus-fyne.exe and
   choose "Run as administrator". Without it, connecting fails and the error
   says "create wintun adapter".

2. WINDOWS WILL WARN THAT THE PROGRAM IS UNSIGNED. You will get a blue
   "Windows protected your PC" box. This build is not code-signed yet; that
   is a known gap and not a sign that something is wrong with your download.
   Choose "More info", then "Run anyway". Check the download against its
   published hash instead -- see CHECKING WHAT YOU DOWNLOADED below.

3. 64-BIT WINDOWS. There is no 32-bit or ARM build in this bundle.


SETTING IT UP

Open bacchus-fyne.config.json in Notepad. It ships as a template with
placeholder hosts, and the client cannot connect until you replace them with
the endpoints your operator gave you:

  "coordinators": ["your-coordinator-host:8080"],
  "stun":         "stun:your-coordinator-host:3478",
  "turn":         "turn:your-coordinator-host:3478",
  "turnUser":     "bacchus",
  "turnPass":     "the password you were given"

"coordinators" is a list: give it more than one and the client rotates
between them, so one being blocked does not take you offline.

Everything below those lines already has a working default. Some of it can
also be changed inside the app, in Settings.

Then start bacchus-fyne.exe as Administrator and press Connect.


WHAT IT DOES TO YOUR MACHINE WHILE CONNECTED

It routes this device -- not just a browser -- through the tunnel: a network
adapter, a change to this machine's routing, and a fail-closed kill switch
that blocks outbound traffic if the tunnel dies, so nothing leaves in the
clear at the moment you think you are protected.

All of that is put back when you disconnect or quit. If the program is killed
outright, the kill switch deliberately leaves the machine offline rather than
leaking; start bacchus-fyne.exe again and it restores normal networking on
startup.


WHAT IT LEAVES BEHIND

Your settings stay in this folder, in bacchus-fyne.config.json, and they go
when the folder goes.

One exception worth knowing about: if you turn on automatic path selection
(the transport pool) in Settings, the client remembers which paths worked in
%APPDATA%\Bacchus\selection. Delete that folder too if you want nothing left
behind. With the settings this bundle ships, nothing is written there.


CHECKING WHAT YOU DOWNLOADED

Every release publishes a SHA256SUMS.txt covering the exact files it shipped.
If you got this bundle from a mirror, a messenger or a USB stick -- which is
how it is meant to travel -- the hash is the part that tells you the bytes are
the ones that were published. In PowerShell:

  Get-FileHash .\bacchus-fyne-{{VERSION}}-windows-amd64.zip -Algorithm SHA256

and compare it with the published value, ideally obtained by a different route
than the file itself.


IF SOMETHING GOES WRONG

  "create wintun adapter"
      Two causes, and they look identical. Either the program is not running
      as Administrator, or wintun.dll is not in this folder next to
      bacchus-fyne.exe. Check both.

  Connect fails immediately with a configuration error
      The placeholder hosts in bacchus-fyne.config.json have not been
      replaced. See SETTING IT UP.

  The app starts but the button does nothing useful
      The coordinator you configured has to be reachable and running.

  You are offline after a crash
      That is the kill switch holding the machine closed, which is what it is
      for. Start bacchus-fyne.exe again; it detects the leftover lockdown and
      restores normal networking.


LICENCE

Bacchus is free software under the GNU Affero General Public License version
3. The source, the full licence text and the issue tracker:

  https://github.com/bacchus-vpn/bacchus

wintun.dll is not ours and is not under that licence -- see
LICENSE.wintun.txt.
