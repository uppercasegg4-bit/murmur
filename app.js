/* =====================================================================
   Chat Aman P2P — app.js (final lengkap)
   ===================================================================== */
(function () {
  "use strict";

  /* ---------- State ---------- */
  var state = {
    me: null,
    peerId: null,
    conns: {},
    convKeys: {},
    convPass: {},
    activePeer: null,
    unread: {},
    lastSnippet: {},
    lastAt: {},
    verifiedSN: {},
    currentSN: {}
  };

  var enc = new TextEncoder();
  var dec = new TextDecoder();

  /* ---------- Utility ---------- */
  function $(s) { return document.querySelector(s); }
  function b64(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function unb64(str) {
    var s = atob(str), b = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  function initials(n) {
    var p = String(n || "?").replace(/[^a-zA-Z0-9 ]/g, " ").trim().split(/\s+/);
    if (p.length === 1) return p[0].slice(0, 2).toUpperCase();
    return (p[0][0] + p[p.length - 1][0]).toUpperCase();
  }
  function fmtTime(ts) {
    var d = new Date(ts || Date.now()), now = new Date();
    if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" });
    return d.toLocaleDateString("id-ID", { day: "2-digit", month: "short" });
  }
  function randomId() {
    return Math.random().toString(36).slice(2, 8);
  }

  /* ---------- Kripto ---------- */
  async function deriveConvKey(convPass, userA, userB) {
    if (typeof convPass !== "string" || !convPass) throw new Error("passphrase kosong");
    var pair = [String(userA).toLowerCase(), String(userB).toLowerCase()].sort().join("|");
    var saltInput = enc.encode("chataman-p2p-v1:" + pair);
    var saltHash = await crypto.subtle.digest("SHA-256", saltInput);
    var salt = new Uint8Array(saltHash).slice(0, 16);
    var base = await crypto.subtle.importKey("raw", enc.encode(convPass), { name: "PBKDF2" }, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: 250000, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
  }

  async function safetyNumber(key) {
    var raw = await crypto.subtle.exportKey("raw", key);
    var h = await crypto.subtle.digest("SHA-256", raw);
    var hx = Array.from(new Uint8Array(h)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    return hx.slice(0, 32).toUpperCase().match(/.{1,4}/g).join(" ");
  }

  async function encryptText(key, plain) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, enc.encode(plain));
    return { iv: b64(iv), ct: b64(ct) };
  }

  async function decryptText(key, payload) {
    try {
      var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(payload.iv) }, key, unb64(payload.ct));
      return dec.decode(pt);
    } catch (e) { return "[pesan tidak bisa didekripsi]"; }
  }

  async function encryptBytes(key, bytes) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, bytes);
    return { iv: b64(iv), ct: b64(ct) };
  }

  async function decryptBytes(key, payload) {
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(payload.iv) }, key, unb64(payload.ct));
    return new Uint8Array(pt);
  }

  /* ---------- IndexedDB ---------- */
  var dbPromise = null;
  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise(function (resolve, reject) {
      var req = indexedDB.open("chataman-p2p", 1);
      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains("messages")) db.createObjectStore("messages", { keyPath: "id", autoIncrement: true });
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
    return dbPromise;
  }
  async function saveMessage(msg) {
    try {
      var db = await openDB();
      var tx = db.transaction("messages", "readwrite");
      tx.objectStore("messages").add(msg);
      return new Promise(function (res) { tx.oncomplete = res; });
    } catch (e) {}
  }
  async function loadMessages(peer) {
    try {
      var db = await openDB();
      var tx = db.transaction("messages", "readonly");
      var store = tx.objectStore("messages");
      var all = await new Promise(function (res) { var r = store.getAll(); r.onsuccess = function () { res(r.result || []); }; });
      return all.filter(function (m) {
        return (m.from === peer && m.to === state.me) || (m.from === state.me && m.to === peer);
      });
    } catch (e) { return []; }
  }
  async function deleteMessage(id) {
    try {
      var db = await openDB();
      var tx = db.transaction("messages", "readwrite");
      tx.objectStore("messages").delete(id);
    } catch (e) {}
  }
  async function clearMessages(peer) {
    try {
      var db = await openDB();
      var tx = db.transaction("messages", "readwrite");
      var store = tx.objectStore("messages");
      var all = await new Promise(function (res) { var r = store.getAll(); r.onsuccess = function () { res(r.result || []); }; });
      all.forEach(function (m) {
        if ((m.from === peer && m.to === state.me) || (m.from === state.me && m.to === peer)) store.delete(m.id);
      });
      return new Promise(function (res) { tx.oncomplete = res; });
    } catch (e) {}
  }

  /* ---------- localStorage helpers ---------- */
  function saveVerified() {
    try { localStorage.setItem("chataman.verifiedsn", JSON.stringify(state.verifiedSN)); } catch (e) {}
  }
  function loadVerified() {
    try {
      var all = JSON.parse(localStorage.getItem("chataman.verifiedsn") || "{}");
      state.verifiedSN = all || {};
    } catch (e) { state.verifiedSN = {}; }
  }
  function saveConvPass(peer, pass) {
    try {
      var all = JSON.parse(localStorage.getItem("chataman.convpass") || "{}");
      all[peer] = pass;
      localStorage.setItem("chataman.convpass", JSON.stringify(all));
    } catch (e) {}
  }
  function loadConvPass(peer) {
    try {
      var all = JSON.parse(localStorage.getItem("chataman.convpass") || "{}");
      return all[peer] || "";
    } catch (e) { return ""; }
  }
  function restoreConvPass() {
    try {
      var all = JSON.parse(localStorage.getItem("chataman.convpass") || "{}");
      Object.keys(all).forEach(function (peer) {
        state.convPass[peer] = all[peer];
        deriveConvKey(all[peer], state.me, peer).then(function (k) {
          state.convKeys[peer] = k;
          safetyNumber(k).then(function (sn) {
            state.currentSN[peer] = sn;
            renderPeers();
          });
        });
      });
    } catch (e) {}
  }

  /* ---------- PeerJS ---------- */
  function createPeer(id) {
    return new Peer(id, {
      debug: 1,
      config: { iceServers: [{ urls: "stun:stun.l.google.com:19302" }, { urls: "stun:stun1.l.google.com:19302" }] }
    });
  }

  /* ---------- Login ---------- */
  function initLogin() {
    var userInput = $("#user");
    var remember = $("#remember");
    var savedUser = localStorage.getItem("chataman.user") || "";
    if (savedUser) userInput.value = savedUser;

    var myIdEl = $("#myId");
    var btnCopy = $("#btnCopyId");
    var btnMasuk = $("#btnMasuk");

    function generateId() {
      var u = (userInput.value || "user").trim().toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12) || "user";
      return u + "-" + randomId();
    }
    function updateId() {
      var id = generateId();
      myIdEl.textContent = id;
      myIdEl.setAttribute("data-id", id);
    }
    userInput.addEventListener("input", updateId);
    updateId();

    btnCopy.addEventListener("click", function () {
      var id = myIdEl.getAttribute("data-id");
      navigator.clipboard.writeText(id).then(function () {
        btnCopy.textContent = "Tersalin!";
        setTimeout(function () { btnCopy.textContent = "Salin"; }, 1500);
      });
    });

    btnMasuk.addEventListener("click", function () {
      var u = (userInput.value || "").trim();
      if (!u) { alert("Isi nama pengguna."); return; }
      var id = myIdEl.getAttribute("data-id");
      if (remember.checked) localStorage.setItem("chataman.user", u);
      else localStorage.removeItem("chataman.user");
      startApp(u, id);
    });
  }

  /* ---------- Start app ---------- */
  function startApp(username, peerId) {
    state.me = username.toLowerCase().replace(/[^a-z0-9]/g, "") || "user";
    $("#login").hidden = true;
    $("#app").hidden = false;
    $("#me").textContent = username;
    if (window.innerWidth <= 820) $("#app").classList.add("show-list");

    var myIdSmall = $("#myIdSmall");
    myIdSmall.textContent = "ID: " + peerId;
    myIdSmall.addEventListener("click", function () {
      navigator.clipboard.writeText(peerId).then(function () {
        myIdSmall.textContent = "ID: " + peerId + " (tersalin)";
        setTimeout(function () { myIdSmall.textContent = "ID: " + peerId; }, 1500);
      });
    });

    state.peerId = createPeer(peerId);
    state.peerId.on("open", function () {
      restoreConvPass();
      loadVerified();
    });
    state.peerId.on("connection", function (conn) { handleConnection(conn); });
    state.peerId.on("error", function (err) {
      console.error("Peer error:", err);
      if (err.type === "unavailable-id") alert("ID sudah dipakai. Muat ulang halaman.");
      else if (err.type === "network") alert("Masalah jaringan. Cek koneksi internet.");
    });
    bindApp();
  }

  /* ---------- Connection ---------- */
  function handleConnection(conn) {
    var peer = conn.peer;
    state.conns[peer] = conn;
    conn.on("open", function () {
      renderPeers();
      var chip = $("#connChip");
      if (state.activePeer === peer && chip) chip.hidden = false;
      updatePeerSub(peer);
    });
    conn.on("data", async function (data) {
      if (!data || !data.type) return;
      await handleIncoming(peer, data);
    });
    conn.on("close", function () {
      delete state.conns[peer];
      renderPeers();
      updatePeerSub(peer);
    });
    conn.on("error", function (e) { console.error("Conn error:", e); });
  }

  function updatePeerSub(peer) {
    if (state.activePeer !== peer) return;
    var sub = $("#peerSub");
    if (!sub) return;
    var online = state.conns[peer] && state.conns[peer].open;
    var verified = state.verifiedSN[peer];
    var currentSN = state.currentSN[peer];
    var text = online ? "terhubung (P2P)" : "belum terhubung";
    if (verified && currentSN && verified !== currentSN) text += " · 🚨 SN berubah";
    else if (verified) text += " · ✅ terverifikasi";
    sub.textContent = text;
  }

  function connectTo(peerId) {
    if (!state.peerId || !state.peerId.open) { alert("Belum terhubung ke jaringan. Tunggu sebentar."); return; }
    if (peerId === state.peerId.id) { alert("Tidak bisa menghubungi diri sendiri."); return; }
    if (state.conns[peerId] && state.conns[peerId].open) { selectPeer(peerId); return; }
    var conn = state.peerId.connect(peerId, { reliable: true });
    handleConnection(conn);
    setTimeout(function () {
      if (conn.open) selectPeer(peerId);
      else alert("Gagal terhubung ke " + peerId + ". Pastikan ID benar dan teman Anda sedang online.");
    }, 4000);
  }

  /* ---------- Incoming ---------- */
  async function handleIncoming(peer, data) {
    // Cek SN berubah
    if (state.convKeys[peer] && state.verifiedSN[peer]) {
      var snNow = await safetyNumber(state.convKeys[peer]);
      state.currentSN[peer] = snNow;
      if (state.verifiedSN[peer] !== snNow) {
        showToast(peer, "🚨 SAFETY NUMBER BERUBAH — kemungkinan MITM!");
        beep();
      }
    }

    if (data.type === "text") {
      var key = state.convKeys[peer];
      if (!key) { showToast(peer, "Pesan masuk, atur passphrase dulu"); return; }
      var plain = await decryptText(key, data.payload);
      addMessageBubble({ from: peer, to: state.me, at: data.at, type: "text", plain: plain }, false, peer);
      await saveMessage({ from: peer, to: state.me, at: data.at, type: "text", plain: plain });
      bumpSnippet(peer, plain);
      if (state.activePeer !== peer) {
        state.unread[peer] = (state.unread[peer] || 0) + 1;
        showToast(peer, plain.slice(0, 80));
      }
      renderPeers();
    } else if (data.type === "file") {
      var key2 = state.convKeys[peer];
      if (!key2) { showToast(peer, "File masuk, atur passphrase dulu"); return; }
      try {
        var bytes = await decryptBytes(key2, data.payload);
        var blob = new Blob([bytes], { type: data.mime });
        var url = URL.createObjectURL(blob);
        addMessageBubble({ from: peer, to: state.me, at: data.at, type: "file", name: data.name, mime: data.mime, url: url, size: data.size }, false, peer);
        await saveMessage({ from: peer, to: state.me, at: data.at, type: "file", name: data.name, mime: data.mime, size: data.size });
        bumpSnippet(peer, "📄 " + data.name);
        if (state.activePeer !== peer) {
          state.unread[peer] = (state.unread[peer] || 0) + 1;
          showToast(peer, "📄 " + data.name);
        }
        renderPeers();
      } catch (e) { showToast(peer, "File tidak bisa didekripsi"); }
    }
  }

  /* ---------- Kirim ---------- */
  async function sendText(text) {
    var peer = state.activePeer;
    if (!peer) return;
    var key = state.convKeys[peer];
    if (!key) { alert("Atur passphrase percakapan dulu (klik 🔑)."); return; }
    var conn = state.conns[peer];
    if (!conn || !conn.open) { alert("Belum terhubung ke " + peer); return; }

    var payload = await encryptText(key, text);
    var ttl = parseInt(($("#ttl") && $("#ttl").value) || "0", 10);
    var at = Date.now();
    conn.send({ type: "text", payload: payload, at: at, ttl: ttl });
    addMessageBubble({ from: state.me, to: peer, at: at, type: "text", plain: text }, true, peer);
    var id = await saveMessage({ from: state.me, to: peer, at: at, type: "text", plain: text, ttl: ttl });
    bumpSnippet(peer, text);
    renderPeers();
    if (ttl > 0) scheduleDelete(peer, at, ttl);
  }

  async function sendFile(file) {
    var peer = state.activePeer;
    if (!peer) return;
    var key = state.convKeys[peer];
    if (!key) { alert("Atur passphrase dulu."); return; }
    var conn = state.conns[peer];
    if (!conn || !conn.open) { alert("Belum terhubung."); return; }
    if (file.size > 10 * 1024 * 1024) { alert("File maksimal 10 MB."); return; }

    var buf = await file.arrayBuffer();
    var payload = await encryptBytes(key, new Uint8Array(buf));
    var ttl = parseInt(($("#ttl") && $("#ttl").value) || "0", 10);
    var at = Date.now();
    conn.send({ type: "file", payload: payload, at: at, ttl: ttl, name: file.name, mime: file.type, size: file.size });
    var url = URL.createObjectURL(file);
    addMessageBubble({ from: state.me, to: peer, at: at, type: "file", name: file.name, mime: file.type, url: url, size: file.size }, true, peer);
    await saveMessage({ from: state.me, to: peer, at: at, type: "file", name: file.name, mime: file.type, size: file.size, ttl: ttl });
    bumpSnippet(peer, "📄 " + file.name);
    renderPeers();
    if (ttl > 0) scheduleDelete(peer, at, ttl);
  }

  function scheduleDelete(peer, at, ttl) {
    setTimeout(async function () {
      var msgs = await loadMessages(peer);
      msgs.forEach(function (m) {
        if (m.at === at && m.id) deleteMessage(m.id);
      });
      // Refresh tampilan jika percakapan ini aktif
      if (state.activePeer === peer) {
        var list = $("#list");
        if (list) {
          Array.prototype.slice.call(list.querySelectorAll(".msg")).forEach(function (n) {
            if (parseInt(n.getAttribute("data-at") || "0", 10) === at) n.remove();
          });
        }
      }
    }, ttl * 1000);
  }

  /* ---------- Bubble ---------- */
  function addMessageBubble(m, isMine, peer) {
    var list = $("#list"); if (!list) return;
    var empty = list.querySelector(".empty"); if (empty) empty.style.display = "none";
    var el = document.createElement("div");
    el.className = "msg" + (isMine ? " mine" : "");
    el.setAttribute("data-peer", peer);
    el.setAttribute("data-at", m.at || Date.now());

    if (m.type === "file") {
      if (m.url) {
        if (m.mime && m.mime.indexOf("image/") === 0) {
          var img = document.createElement("img"); img.src = m.url; img.alt = m.name; el.appendChild(img);
        } else if (m.mime && m.mime.indexOf("audio/") === 0) {
          var au = document.createElement("audio"); au.controls = true; au.src = m.url; el.appendChild(au);
        } else {
          var a = document.createElement("a"); a.href = m.url; a.download = m.name; a.textContent = "📄 " + m.name; el.appendChild(a);
        }
      } else {
        var t0 = document.createElement("div"); t0.className = "body"; t0.textContent = "📄 " + m.name; el.appendChild(t0);
      }
    } else {
      var body = document.createElement("div"); body.className = "body"; body.textContent = m.plain || ""; el.appendChild(body);
    }

    var meta = document.createElement("div"); meta.className = "meta";
    var t2 = document.createElement("span");
    t2.textContent = new Date(m.at || Date.now()).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" });
    meta.appendChild(t2); el.appendChild(meta);

    list.appendChild(el);
    if (list.scrollHeight - list.scrollTop - list.clientHeight < 120) list.scrollTop = list.scrollHeight;
  }

  function bumpSnippet(peer, text) {
    state.lastSnippet[peer] = text;
    state.lastAt[peer] = Date.now();
  }

  /* ---------- Peers list ---------- */
  function renderPeers() {
    var box = $("#peerList"); if (!box) return;
    var q = (($("#peerSearch") && $("#peerSearch").value) || "").toLowerCase();
    var all = {};
    Object.keys(state.conns).forEach(function (p) { all[p] = true; });
    Object.keys(state.convKeys).forEach(function (p) { all[p] = true; });
    var arr = Object.keys(all).filter(function (p) { return !q || p.toLowerCase().indexOf(q) !== -1; });
    arr.sort(function (a, b) { return (state.lastAt[b] || 0) - (state.lastAt[a] || 0); });

    box.innerHTML = "";
    if (!arr.length) {
      var e = $("#peersEmpty"); if (e) e.hidden = false;
      return;
    }
    var e2 = $("#peersEmpty"); if (e2) e2.hidden = true;

    arr.forEach(function (p) {
      var el = document.createElement("div");
      el.className = "peer-item" + (p === state.activePeer ? " active" : "") + (state.unread[p] > 0 ? " unread" : "") + (state.conns[p] && state.conns[p].open ? " online" : "");
      el.setAttribute("data-peer", p);

      var av = document.createElement("div"); av.className = "peer-avatar"; av.textContent = initials(p);
      var body = document.createElement("div"); body.className = "peer-body";
      var nm = document.createElement("div"); nm.className = "peer-name";

      var verified = state.verifiedSN[p];
      var currentSN = state.currentSN[p];
      if (verified && currentSN && verified !== currentSN) nm.innerHTML = "🚨 " + p;
      else if (verified) nm.innerHTML = "✅ " + p;
      else nm.textContent = p;

      var sn = document.createElement("div"); sn.className = "peer-snippet"; sn.textContent = state.lastSnippet[p] || "Belum ada pesan";
      body.appendChild(nm); body.appendChild(sn);

      var meta = document.createElement("div"); meta.className = "peer-meta";
      var tm = document.createElement("div"); tm.className = "peer-time"; tm.textContent = state.lastAt[p] ? fmtTime(state.lastAt[p]) : "";
      meta.appendChild(tm);
      if (state.unread[p] > 0) {
        var b = document.createElement("div"); b.className = "badge"; b.textContent = state.unread[p] > 99 ? "99+" : String(state.unread[p]);
        meta.appendChild(b);
      }
      if (verified && currentSN && verified !== currentSN) {
        var warn = document.createElement("div"); warn.textContent = "⚠️"; warn.style.fontSize = "14px";
        meta.appendChild(warn);
      }

      el.appendChild(av); el.appendChild(body); el.appendChild(meta);
      el.addEventListener("click", function () { selectPeer(p); });
      box.appendChild(el);
    });
  }

  async function selectPeer(peer) {
    state.activePeer = peer;
    state.unread[peer] = 0;
    $("#peer").value = peer;
    $("#peerTitle").hidden = false;
    $("#peerName").textContent = peer;
    $("#peerAvatar").textContent = initials(peer);
    $("#composer").hidden = false;
    $("#app").classList.remove("show-list");
    updatePeerSub(peer);

    var chip = $("#connChip");
    if (chip) chip.hidden = !(state.conns[peer] && state.conns[peer].open);

    var list = $("#list");
    Array.prototype.slice.call(list.querySelectorAll(".msg")).forEach(function (n) { n.remove(); });

    var key = state.convKeys[peer];
    if (!key) {
      var p = document.createElement("p");
      p.className = "empty";
      p.textContent = "Passphrase percakapan dengan " + peer + " belum diatur. Klik 🔑 Passphrase di bawah.";
      list.appendChild(p);
    } else {
      var msgs = await loadMessages(peer);
      if (!msgs.length) {
        var p2 = document.createElement("p");
        p2.className = "empty";
        p2.textContent = "Belum ada pesan. Tulis pesan pertama Anda.";
        list.appendChild(p2);
      } else {
        msgs.sort(function (a, b) { return a.at - b.at; });
        msgs.forEach(function (m) {
          addMessageBubble({
            from: m.from, to: m.to, at: m.at, type: m.type, plain: m.plain,
            name: m.name, mime: m.mime, size: m.size
          }, m.from === state.me, peer);
        });
      }
    }
    renderPeers();
  }

  /* ---------- Toast & beep ---------- */
  function showToast(peer, text) {
    var wrap = $("#toasts"); if (!wrap) return;
    var t = document.createElement("div"); t.className = "toast";
    var av = document.createElement("div"); av.className = "tav"; av.textContent = initials(peer);
    var body = document.createElement("div");
    var nm = document.createElement("div"); nm.className = "tname"; nm.textContent = peer;
    var tx = document.createElement("div"); tx.className = "ttext"; tx.textContent = text;
    body.appendChild(nm); body.appendChild(tx);
    var close = document.createElement("button"); close.className = "tx"; close.textContent = "✕";
    close.addEventListener("click", function (e) { e.stopPropagation(); t.remove(); });
    t.appendChild(av); t.appendChild(body); t.appendChild(close);
    t.addEventListener("click", function () { selectPeer(peer); t.remove(); });
    wrap.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.remove(); }, 6000);
    beep();
  }

  var actx = null;
  function beep() {
    try {
      if (!actx) actx = new (window.AudioContext || window.webkitAudioContext)();
      if (actx.state === "suspended") actx.resume();
      var o = actx.createOscillator(), g = actx.createGain();
      o.type = "sine"; o.frequency.value = 880;
      g.gain.setValueAtTime(0.0001, actx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.08, actx.currentTime + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + 0.12);
      o.connect(g).connect(actx.destination);
      o.start(); o.stop(actx.currentTime + 0.14);
    } catch (e) {}
  }

  /* ---------- Safety number panel ---------- */
  async function showSafetyPanel() {
    var peer = state.activePeer;
    if (!peer) { alert("Pilih percakapan dulu."); return; }
    if (!state.convKeys[peer]) { alert("Atur passphrase dulu (klik 🔑)."); return; }

    var sn = await safetyNumber(state.convKeys[peer]);
    state.currentSN[peer] = sn;
    var verified = state.verifiedSN[peer];
    var isVerified = verified === sn;

    var s = $("#safety");
    s.hidden = false;
    s.innerHTML = "";

    var title = document.createElement("div");
    title.innerHTML = "<b>Safety Number dengan " + peer + "</b>";
    s.appendChild(title);

    var code = document.createElement("div");
    code.className = "sncode";
    code.textContent = sn;
    s.appendChild(code);

    var status = document.createElement("div");
    status.style.fontSize = "13px";
    if (isVerified) {
      status.innerHTML = "✅ <b style='color:var(--ok)'>Terverifikasi</b> — nomor ini sudah Anda bandingkan dan cocok.";
    } else if (verified && verified !== sn) {
      status.innerHTML = "🚨 <b style='color:var(--danger)'>BERUBAH!</b> Nomor berbeda dari yang pernah diverifikasi. Kemungkinan MITM. Hubungi " + peer + " lewat jalur lain SEGERA.";
    } else {
      status.innerHTML = "⚠️ <b style='color:var(--warn)'>Belum diverifikasi.</b> Bandingkan nomor ini dengan " + peer + " lewat telepon/tatap muka.";
    }
    s.appendChild(status);

    var btn = document.createElement("button");
    btn.style.marginTop = "10px";
    btn.style.padding = "7px 14px";
    btn.style.fontSize = "13px";
    if (isVerified) {
      btn.className = "btn";
      btn.textContent = "Batalkan verifikasi";
      btn.addEventListener("click", function () {
        delete state.verifiedSN[peer];
        saveVerified();
        showSafetyPanel();
        renderPeers();
      });
    } else {
      btn.className = "btn primary";
      btn.textContent = "✓ Saya sudah bandingkan — cocok";
      btn.addEventListener("click", function () {
        if (!confirm("Anda yakin sudah membandingkan nomor ini dengan " + peer + " lewat telepon/tatap muka, dan hasilnya COCOK?")) return;
        state.verifiedSN[peer] = sn;
        saveVerified();
        alert("✅ Aman. Safety Number terverifikasi. Kalau nomor ini berubah di masa depan, Anda akan diperingatkan.");
        showSafetyPanel();
        renderPeers();
      });
    }
    s.appendChild(btn);
  }

  /* ---------- Bind ---------- */
  function bindApp() {
    $("#btnStart").addEventListener("click", function () {
      var v = ($("#peer").value || "").trim();
      if (!v) return;
      connectTo(v);
    });
    $("#peer").addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); $("#btnStart").click(); }
    });
    $("#peerSearch").addEventListener("input", renderPeers);
    $("#btnBack").addEventListener("click", function () { $("#app").classList.add("show-list"); });

    $("#btnSend").addEventListener("click", function () {
      var t = $("#text").value.trim();
      if (!t) return;
      $("#text").value = "";
      sendText(t);
    });
    $("#text").addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#btnSend").click(); }
    });

    $("#btnAttach").addEventListener("click", function () { $("#file").click(); });
    $("#file").addEventListener("change", function () {
      var f = $("#file").files[0]; if (!f) return;
      sendFile(f);
      $("#file").value = "";
    });

    $("#btnMic").addEventListener("click", function () { $("#audioFile").click(); });
    $("#audioFile").addEventListener("change", function () {
      var f = $("#audioFile").files[0]; if (!f) return;
      sendFile(f);
      $("#audioFile").value = "";
    });

    $("#btnConvPass").addEventListener("click", async function () {
      var peer = state.activePeer;
      if (!peer) { alert("Pilih percakapan dulu."); return; }
      var pass = prompt("Passphrase percakapan dengan " + peer + "\n(disepakati lewat telepon/tatap muka)\n\nMinimal 6 kata:");
      if (!pass) return;
      try {
        var key = await deriveConvKey(pass, state.me, peer);
        state.convKeys[peer] = key;
        state.convPass[peer] = pass;
        saveConvPass(peer, pass);
        var sn = await safetyNumber(key);
        state.currentSN[peer] = sn;

        var prevVerified = state.verifiedSN[peer];
        var warning = "";
        if (prevVerified && prevVerified !== sn) {
          warning = "\n\n⚠️ PERINGATAN: Safety Number BERUBAH dari yang pernah Anda verifikasi!\nIni bisa berarti ada penyusup (MITM). JANGAN lanjut chat sampai Anda verifikasi ulang lewat telepon.";
        }

        alert("Passphrase tersimpan.\n\nSafety Number:\n" + sn + "\n\nBandingkan nomor ini dengan " + peer + " lewat telepon/tatap muka.\nKalau SAMA di kedua sisi, tidak ada penyusup." + warning);
        selectPeer(peer);
        renderPeers();
      } catch (e) { alert("Gagal: " + e.message); }
    });

    $("#btnSafety").addEventListener("click", showSafetyPanel);

    $("#btnDel").addEventListener("click", async function () {
      var peer = state.activePeer;
      if (!peer) return;
      if (!confirm("Hapus percakapan dengan " + peer + "?")) return;
      await clearMessages(peer);
      state.lastSnippet[peer] = "";
      state.lastAt[peer] = 0;
      selectPeer(peer);
      renderPeers();
    });

    $("#btnLogout").addEventListener("click", function () {
      if (!confirm("Keluar? Percakapan tersimpan di perangkat ini.")) return;
      location.reload();
    });

    $("#btnWipe").addEventListener("click", async function () {
      if (!confirm("Hapus SEMUA data lokal (pesan, passphrase, ID)?")) return;
      try {
        var db = await openDB();
        var tx = db.transaction("messages", "readwrite");
        tx.objectStore("messages").clear();
        await new Promise(function (r) { tx.oncomplete = r; });
      } catch (e) {}
      localStorage.clear();
      location.reload();
    });

    $("#btnTheme").addEventListener("click", function () {
      var cur = localStorage.getItem("chataman.theme") || "auto";
      var next = cur === "auto" ? "light" : cur === "light" ? "dark" : "auto";
      if (next === "auto") localStorage.removeItem("chataman.theme"); else localStorage.setItem("chataman.theme", next);
      applyTheme(next);
    });
    applyTheme(localStorage.getItem("chataman.theme") || "auto");

    document.addEventListener("click", function (e) {
      var b = e.target.closest && e.target.closest(".emoji-bar button[data-emoji]");
      if (b) {
        var inp = $("#text"); if (!inp) return;
        var emoji = b.getAttribute("data-emoji");
        var start = inp.selectionStart || 0, end = inp.selectionEnd || 0;
        inp.value = inp.value.slice(0, start) + emoji + inp.value.slice(end);
        var pos = start + emoji.length;
        inp.setSelectionRange(pos, pos); inp.focus();
      }
    });
  }

  function applyTheme(mode) {
    var r = document.documentElement;
    if (mode === "light") {
      r.style.colorScheme = "light";
      r.style.setProperty("--bg", "#eef1f5"); r.style.setProperty("--panel", "#fff");
      r.style.setProperty("--ink", "#17202a"); r.style.setProperty("--mute", "#5d6b7a");
      r.style.setProperty("--line", "#d3dae2"); r.style.setProperty("--theirs", "#e3e8ee");
    } else if (mode === "dark") {
      r.style.colorScheme = "dark";
      r.style.setProperty("--bg", "#0e1318"); r.style.setProperty("--panel", "#161d25");
      r.style.setProperty("--ink", "#e6ebf0"); r.style.setProperty("--mute", "#93a1b0");
      r.style.setProperty("--line", "#2b3641"); r.style.setProperty("--theirs", "#232d37");
    } else {
      r.style.colorScheme = "";
      ["--bg","--panel","--ink","--mute","--line","--theirs"].forEach(function (v) { r.style.removeProperty(v); });
    }
  }

  document.addEventListener("DOMContentLoaded", initLogin);
})();
