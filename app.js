"use strict";

const EXPLOIT_URL = "notify.html";
const OFFSETS_URL = "offsets/offsets.json";

const runBtn = document.getElementById("run");
const msg = document.getElementById("msg");
const fwDisplay = document.getElementById("fw-display");
const statusDot = document.getElementById("status-dot");
const toggleParamsBtn = document.getElementById("toggle-params");
const paramJsonCode = document.getElementById("param-json");

const autoConsoleIp = document.getElementById("auto-console-ip");
const autoConsolePort = document.getElementById("auto-console-port");
const toastContainer = document.getElementById("toast-container");

let entry = null;

// Toast Notification Helper
function showToast(message, type = "info") {
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(-10px)";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// User-Agent environment detection
const m = /PlayStation 5\/(\d+)\.(\d+)/.exec(navigator.userAgent);
const fw = m ? `${m[1].padStart(2, "0")}.${m[2].padStart(2, "0")}` : null;

function isIPv4(str) {
    if (!str || typeof str !== "string") return false;
    const parts = str.split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => {
        const n = parseInt(p, 10);
        return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
    });
}

function isPrivateLanIP(ip) {
    if (!isIPv4(ip)) return false;
    if (ip.startsWith("127.") || ip.startsWith("0.")) return false;
    return (
        ip.startsWith("192.168.") ||
        ip.startsWith("10.") ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
        ip.startsWith("169.254.")
    );
}

function decodeMDNSSuffix(candidateStr) {
    const m = /([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.local/i.exec(candidateStr);
    if (m && m[1]) {
        const hex = m[1];
        const p1 = parseInt(hex.substr(0, 2), 16);
        const p2 = parseInt(hex.substr(2, 2), 16);
        const p3 = parseInt(hex.substr(4, 2), 16);
        const p4 = parseInt(hex.substr(6, 2), 16);
        const ip = `${p1}.${p2}.${p3}.${p4}`;
        if (isPrivateLanIP(ip)) return ip;
    }
    return null;
}

let detectedHost = "127.0.0.1";
let detectedPort = "9026";

// 1. Check URL parameters
const APP_Q_PARAMS = new URLSearchParams(window.location.search);
const appQIp = APP_Q_PARAMS.get("ip") || APP_Q_PARAMS.get("host");
const appQPort = APP_Q_PARAMS.get("port");

if (appQPort && /^\d+$/.test(appQPort)) {
    detectedPort = appQPort;
}

if (appQIp && (isIPv4(appQIp) || isPrivateLanIP(appQIp))) {
    detectedHost = appQIp;
} else {
    // 2. Check localStorage saved IP
    let savedIp = null;
    try { savedIp = localStorage.getItem("ps5_target_ip"); } catch (e) {}
    if (savedIp && isIPv4(savedIp)) {
        detectedHost = savedIp;
    } else if (isIPv4(window.location.hostname)) {
        detectedHost = window.location.hostname;
    }
}

function updateAppHostDisplay() {
    if (autoConsoleIp) {
        if (detectedHost && !detectedHost.includes(".github.io")) {
            autoConsoleIp.textContent = detectedHost;
        } else {
            autoConsoleIp.textContent = "127.0.0.1";
        }
    }
    if (autoConsolePort) autoConsolePort.textContent = detectedPort;
}

updateAppHostDisplay();

// 3. WebRTC Detection
(function detectAppLocalIP() {
    try {
        const PeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
        if (!PeerConnection) return;

        const pc = new PeerConnection({
            iceServers: [
                { urls: "stun:stun.l.google.com:19302" },
                { urls: "stun:stun1.l.google.com:19302" }
            ]
        });

        if (typeof pc.createDataChannel === "function") {
            pc.createDataChannel("lan_check");
        }

        const processCandidate = (c) => {
            if (!c) return;
            const rawMatch = /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/.exec(c);
            if (rawMatch && rawMatch[1] && isPrivateLanIP(rawMatch[1])) {
                detectedHost = rawMatch[1];
                updateAppHostDisplay();
                try { localStorage.setItem("ps5_target_ip", detectedHost); } catch (e) {}
                return;
            }
            const mdnsIP = decodeMDNSSuffix(c);
            if (mdnsIP) {
                detectedHost = mdnsIP;
                updateAppHostDisplay();
                try { localStorage.setItem("ps5_target_ip", detectedHost); } catch (e) {}
            }
        };

        pc.onicecandidate = (e) => {
            if (e && e.candidate && e.candidate.candidate) {
                processCandidate(e.candidate.candidate);
            }
        };

        pc.createOffer().then(sdp => {
            if (sdp && sdp.sdp) {
                sdp.sdp.split("\r\n").forEach(processCandidate);
            }
            return pc.setLocalDescription(sdp);
        }).catch(() => {});
    } catch (err) {}
})();

if (autoConsoleIp) {
    autoConsoleIp.style.cursor = "pointer";
    autoConsoleIp.addEventListener("click", function() {
        const val = prompt("Enter Target Host IP:", detectedHost);
        if (val !== null) {
            const trimmed = val.trim();
            if (trimmed) {
                detectedHost = trimmed;
                updateAppHostDisplay();
                try { localStorage.setItem("ps5_target_ip", detectedHost); } catch(e) {}
            }
        }
    });
}

function fwNum(s) {
    const p = s.split(".");
    return parseInt(p[0], 10) * 100 + parseInt(p[1], 10);
}

function nearest(data, target) {
    const want = fwNum(target);
    let best = null, bestd = 1e9;
    for (const k in data) {
        const d = Math.abs(fwNum(k) - want);
        if (d < bestd) { bestd = d; best = k; }
    }
    return best;
}

if (toggleParamsBtn) {
    toggleParamsBtn.addEventListener("click", function() {
        paramJsonCode.classList.toggle("hidden");
        toggleParamsBtn.textContent = paramJsonCode.classList.contains("hidden") ? "Show Details" : "Hide Details";
    });
}

// Fetch offsets database with root folder fallback
fetch(OFFSETS_URL, { cache: "no-store" })
    .then(function (r) { 
        if (!r.ok) return fetch("offsets.json", { cache: "no-store" });
        return r;
    })
    .then(function (r) {
        if (!r.ok) throw new Error("HTTP error " + r.status);
        return r.json();
    })
    .then(function (data) {
        if (!fw) {
            msg.textContent = "Demo Mode (Standard Browser)";
            if (fwDisplay) fwDisplay.textContent = "Standard Browser (Demo)";
            const demoKey = Object.keys(data)[0];
            if (demoKey) {
                entry = data[demoKey];
                runBtn.classList.remove("disabled");
                runBtn.removeAttribute("disabled");
                if (paramJsonCode) paramJsonCode.textContent = JSON.stringify(entry, null, 2);
            }
            showToast("Demo mode enabled: desktop browser", "info");
            return;
        }

        if (fwDisplay) fwDisplay.textContent = `PS5 Firmware ${fw}`;

        entry = data[fw];
        if (entry) {
            msg.textContent = `Firmware ${fw} supported`;
            runBtn.classList.remove("disabled");
            runBtn.removeAttribute("disabled");
            if (statusDot) statusDot.className = "status-indicator ready";
            if (paramJsonCode) paramJsonCode.textContent = JSON.stringify(entry, null, 2);
            showToast(`PS5 FW ${fw} offsets matched!`, "success");
            return;
        }

        const near = nearest(data, fw);
        if (near) {
            entry = data[near];
            msg.textContent = `FW ${fw}: matched using ${near} profile`;
            runBtn.classList.remove("disabled");
            runBtn.removeAttribute("disabled");
            if (statusDot) statusDot.className = "status-indicator ready";
            if (paramJsonCode) paramJsonCode.textContent = JSON.stringify(entry, null, 2);
            showToast(`Matched FW ${fw} with ${near} offsets`, "success");
        } else {
            msg.textContent = `Firmware ${fw} not supported`;
            if (statusDot) statusDot.className = "status-indicator error";
            showToast(`Firmware ${fw} is not in offsets configuration`, "error");
        }
    })
    .catch(function () {
        msg.textContent = "Failed to load offsets configuration";
        if (statusDot) statusDot.className = "status-indicator error";
        showToast("Error loading offsets.json", "error");
    });

// RUN button event listener (Uses automatically detected host IP and port)
runBtn.addEventListener("click", function () {
    if (!entry) return;

    showToast(`Executing parameters -> ${detectedHost}:${detectedPort}`, "success");
    if (msg) msg.textContent = `Connecting to ${detectedHost}:${detectedPort}...`;

    const q = new URLSearchParams();
    q.set("go", "1");
    q.set("fw", fw || "demo");
    q.set("host", detectedHost);
    q.set("ip", detectedHost);
    q.set("port", detectedPort);
    if (entry.hc) q.set("hc", entry.hc.join(","));
    q.set("gd", entry.gd || "");
    q.set("notify", entry.nt || "");
    q.set("gps", entry.gps || "");
    q.set("gpe", entry.gpe || "");
    q.set("cls", entry.cls || "");
    q.set("cle", entry.cle || "");
    q.set("ers", entry.ers || "");
    q.set("ere", entry.ere || "");

    setTimeout(() => {
        location.href = `${EXPLOIT_URL}?${q.toString()}`;
    }, 400);
});
