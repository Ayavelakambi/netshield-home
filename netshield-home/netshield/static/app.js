/* NetShield Home — real-time client (Socket.IO).
   Pages are server-rendered; Socket.IO pushes device join/leave, new
   alerts, control-state changes and scan completion without a refresh. */
(function () {
  "use strict";
  var socket;
  try {
    socket = io();
  } catch (e) {
    return; // socket.io client failed to load (offline preview) — pages still work
  }

  function toast(msg, kind) {
    var host = document.getElementById("toasts");
    if (!host) {
      host = document.createElement("div");
      host.id = "toasts";
      document.body.appendChild(host);
    }
    var el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(function () { el.remove(); }, 7000);
  }

  function refreshAlertBadge() {
    fetch("/alerts/api/count", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var el = document.getElementById("alert-count");
        if (el) {
          el.textContent = d.total || "";
          el.style.display = d.total ? "" : "none";
        }
      })
      .catch(function () {});
  }

  socket.on("device_join", function (d) {
    toast("New device joined: " + (d.display_name || d.ip) +
      (d.is_new ? " (first time seen)" : ""), "info");
    refreshAlertBadge();
  });
  socket.on("device_leave", function (d) {
    toast("Device left the network: " + (d.nickname || d.mac), "warn");
  });
  socket.on("alert", function (a) {
    toast("[" + a.severity + "] " + a.message, "alert");
    refreshAlertBadge();
  });
  socket.on("control_state", function (c) {
    // live control-state chips: [data-control-state] on rows, [data-control-state-chip] on chips
    var chips = document.querySelectorAll('[data-control-state-chip="' + c.mac + '"]');
    for (var i = 0; i < chips.length; i++) {
      chips[i].textContent = c.control_state;
      chips[i].className = "chip ctl-" + c.control_state;
    }
    var rows = document.querySelectorAll('[data-control-state="' + c.mac + '"]');
    for (var j = 0; j < rows.length; j++) {
      rows[j].textContent = c.control_state;
      rows[j].className = "chip ctl-" + c.control_state;
    }
  });
  socket.on("scan_complete", function (s) {
    toast("Scan of " + s.device_ip + " complete: " + s.open_count +
      " open port(s), " + s.high_risk + " high/critical", "info");
  });
    socket.on("hostname", function (h) {
      // a device name was resolved in the background — update the row live
      var cell = document.querySelector('td[data-mac="' + h.mac + '"]');
      if (cell) {
        var strong = cell.querySelector(".dev-name");
        if (strong) {
          var current = strong.textContent;
          // only replace when the current text is an IP (no nickname set)
          if (/^\d+\.\d+\.\d+\.\d+$/.test(current.trim())) {
            strong.textContent = h.hostname;
          }
        }
      }
      // also refresh the topology label (SVG text carries data-mac)
      var t = document.querySelector('text[data-mac="' + h.mac + '"]');
      if (t) {
        var cur = t.textContent;
        if (/^\d+\.\d+\.\d+\.\d+$/.test(cur.trim())) {
          t.textContent = h.hostname.slice(0, 16);
        }
      }
    });

  refreshAlertBadge();
  setInterval(refreshAlertBadge, 60000);
})();
