/* Copyright 2026 Amir Sibaee (https://as86.pro) */
/* SPDX-License-Identifier: Apache-2.0 */
/* Shared helpers for the UserTools for cPanel pages. Plain JS, no framework. */
"use strict";

var UserTools = (function () {
    // UAPI base URL. cPanel serves this page under /cpsessTOKEN/... and the
    // session token is required for cookie-based /execute calls, so
    // derive it from the first path segment.
    function apiBase(module) {
        var seg = window.location.pathname.split("/")[1] || "";
        return "/" + seg + "/execute/" + (module || "UserTools") + "/";
    }
    function encodeParams(params) {
        var parts = [];
        Object.keys(params || {}).forEach(function (k) {
            var v = params[k];
            var list = Array.isArray(v) ? v : [v];
            list.forEach(function (item) {
                parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(item));
            });
        });
        return parts.join("&");
    }
    function callApi(fn, params, method, module) {
        var url = apiBase(module) + fn;
        var opts = { method: method || "GET", credentials: "same-origin" };
        if (method === "POST") {
            opts.headers = { "Content-Type": "application/x-www-form-urlencoded" };
            opts.body = encodeParams(params);
        } else if (params) {
            url += "?" + encodeParams(params);
        }
        return fetch(url, opts).then(function (resp) {
            if (!resp.ok) {
                throw new Error("request failed: " + resp.status);
            }
            return resp.json();
        }).then(function (json) {
            if (json.errors && json.errors.length) {
                throw new Error(json.errors.join("; "));
            }
            return json.data || {};
        });
    }
    function escHtml(s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;",
                '"': "&quot;", "'": "&#39;" }[c];
        });
    }
    // One shared plural helper for every count on every page. Pass the
    // one- and many-forms (each may contain COUNT); exactly 1 takes the one
    // form, everything else (including 0) takes the many form.
    function plural(n, one, many) {
        var count = Number(n);
        if (!isFinite(count)) { count = 0; }
        var template = (count === 1) ? one : many;
        return String(template).split("COUNT").join(count);
    }
    function copyText(text, btn) {
        function done() {
            if (btn) {
                var old = btn.textContent;
                btn.textContent = "Copied";
                setTimeout(function () { btn.textContent = old; }, 1500);
            }
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done, function () {
                fallback();
            });
        } else {
            fallback();
        }
        function fallback() {
            var ta = document.createElement("textarea");
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand("copy"); } catch (e) { /* ignore */ }
            document.body.removeChild(ta);
            done();
        }
    }
    function toggleAbout() {
        var el = document.getElementById("ut-about");
        if (el) {
            el.style.display = el.style.display === "block" ? "none" : "block";
        }
        return false;
    }
    function csvCell(s) {
        var t = String(s == null ? "" : s);
        if (/^[=+\-@\t\r]/.test(t)) { t = "'" + t; }
        if (/[",\n\r]/.test(t)) { return '"' + t.replace(/"/g, '""') + '"'; }
        return t;
    }
    function buildCsv(header, rows) {
        var lines = [header.map(csvCell).join(",")];
        rows.forEach(function (r) {
            lines.push(r.map(csvCell).join(","));
        });
        return lines.join("\r\n") + "\r\n";
    }
    function downloadCsv(filename, csvText) {
        var urlMaker = window.URL || window.webkitURL;
        var blob = new Blob([csvText], { type: "text/csv" });
        var a = document.createElement("a");
        a.href = urlMaker.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () {
            urlMaker.revokeObjectURL(a.href);
            document.body.removeChild(a);
        }, 1000);
    }
    function topDirs(paths, limit) {
        var counts = {};
        paths.forEach(function (p) {
            var top = String((p && p.path) || p || "").split("/")[0] || "/";
            counts[top] = (counts[top] || 0) + 1;
        });
        return Object.keys(counts).sort(function (a, b) {
            return counts[b] - counts[a];
        }).slice(0, limit || 10).map(function (k) {
            return { dir: k, count: counts[k] };
        });
    }
    function flattenDomainsData(data) {
        if (!data) { return []; }
        if (Array.isArray(data)) { return data; }
        var out = [];
        if (data.main_domain && typeof data.main_domain === "object") {
            out.push(data.main_domain);
        }
        ["addon_domains", "sub_domains", "parked_domains", "domains", "data"].forEach(function (k) {
            if (Array.isArray(data[k])) {
                data[k].forEach(function (r) { out.push(r); });
            }
        });
        if (!out.length && data.documentroot) { out.push(data); }
        return out;
    }
    function populateDocroots(selectEl, noneText) {
        return callApi("domains_data", {}, "GET", "DomainInfo").then(function (data) {
            var list = flattenDomainsData(data);
            var usable = [];
            (Array.isArray(list) ? list : []).forEach(function (d) {
                if (d && typeof d.documentroot === "string" && d.documentroot) {
                    usable.push({ domain: d.domain || d.documentroot, root: d.documentroot });
                }
            });
            if (!usable.length) {
                selectEl.disabled = true;
                var opt = document.createElement("option");
                opt.textContent = noneText;
                selectEl.appendChild(opt);
                return [];
            }
            usable.forEach(function (u) {
                var opt = document.createElement("option");
                opt.value = u.root;
                opt.textContent = u.domain;
                selectEl.appendChild(opt);
            });
            return usable;
        }).catch(function () {
            selectEl.disabled = true;
            return [];
        });
    }
    return { apiBase: apiBase, callApi: callApi, escHtml: escHtml,
        copyText: copyText, toggleAbout: toggleAbout, plural: plural,
        csvCell: csvCell, buildCsv: buildCsv, downloadCsv: downloadCsv,
        topDirs: topDirs, flattenDomainsData: flattenDomainsData,
        populateDocroots: populateDocroots };
})();
