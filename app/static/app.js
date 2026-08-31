/* CSRF header for HTMX requests */
document.addEventListener('htmx:configRequest', function (e) {
  var m = document.querySelector('meta[name="csrf-token"]');
  if (m) e.detail.headers['X-CSRF-Token'] = m.content;
});


  /* Persist sidebar <details> open/closed across full page navigations. */
  (function () {
    var KEY = 'secretstore.sidebar.groups';
    function load() {
      try { return JSON.parse(localStorage.getItem(KEY) || '{}') || {}; }
      catch (e) { return {}; }
    }
    function save(state) {
      try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {}
    }
    function apply(root) {
      var state = load();
      (root || document).querySelectorAll('[data-side-group]').forEach(function (el) {
        var id = el.getAttribute('data-side-group');
        if (!id || !Object.prototype.hasOwnProperty.call(state, id)) return;
        el.open = !!state[id];
      });
    }
    /* Remember sections the server opened so a later page cannot collapse them
       just because its endpoint default is different (toggle still wins). */
    function seedOpen(root) {
      var state = load();
      var changed = false;
      (root || document).querySelectorAll('[data-side-group]').forEach(function (el) {
        var id = el.getAttribute('data-side-group');
        if (!id || !el.open || Object.prototype.hasOwnProperty.call(state, id)) return;
        state[id] = true;
        changed = true;
      });
      if (changed) save(state);
    }
    function bind(root) {
      (root || document).querySelectorAll('[data-side-group]').forEach(function (el) {
        if (el.dataset.sideBound === '1') return;
        el.dataset.sideBound = '1';
        el.addEventListener('toggle', function () {
          var id = el.getAttribute('data-side-group');
          if (!id) return;
          var state = load();
          state[id] = !!el.open;
          save(state);
        });
      });
    }
    function sync(root) {
      apply(root);
      seedOpen(root);
      bind(root);
    }
    sync(document);
    document.addEventListener('htmx:afterSwap', function (e) {
      sync(e && e.target ? e.target : document);
      // OOB swaps may replace nodes outside the swap target
      sync(document);
    });
  })();
  /* Mobile sidebar toggle */
  (function () {
    var btn = document.getElementById('side-toggle');
    var backdrop = document.getElementById('side-backdrop');
    var sidebar = document.getElementById('app-sidebar');
    if (!btn || !sidebar) return;
    var close = function () {
      document.body.classList.remove('side-open');
      btn.setAttribute('aria-expanded', 'false');
      btn.setAttribute('aria-label', 'Open navigation menu');
      btn.focus();
    };
    btn.addEventListener('click', function () {
      var open = document.body.classList.toggle('side-open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Close navigation menu' : 'Open navigation menu');
      if (open) {
        var first = sidebar.querySelector('a, button, input, select, summary');
        if (first) first.focus();
      }
    });
    if (backdrop) backdrop.addEventListener('click', close);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && document.body.classList.contains('side-open')) close();
    });
    document.querySelectorAll('.sidebar a.side-nav-link').forEach(function (a) {
      a.addEventListener('click', function () {
        if (window.matchMedia('(max-width: 720px)').matches) close();
      });
    });
  })();

  /* Page subnav tab active state switcher on HTMX navigation */
  document.addEventListener('click', function (e) {
    var link = e.target.closest && e.target.closest('.page-subnav-link');
    if (!link || !link.hasAttribute('hx-get')) return;
    var nav = link.closest('.page-subnav');
    if (!nav) return;
    nav.querySelectorAll('.page-subnav-link').forEach(function (el) {
      el.classList.remove('active');
      el.removeAttribute('aria-current');
    });
    link.classList.add('active');
    link.setAttribute('aria-current', 'page');
  });

  /* User email autocomplete for member fields */
  (function () {
    var list = document.getElementById('user-suggest-list');
    if (!list) return;
    var timer = null;
    var lastQ = '';
    function fill(items) {
      list.innerHTML = '';
      (items || []).forEach(function (it) {
        var o = document.createElement('option');
        o.value = it.email;
        o.label = it.label || it.email;
        list.appendChild(o);
      });
    }
    document.addEventListener('input', function (e) {
      var el = e.target;
      if (!el || !el.classList || !el.classList.contains('user-suggest')) return;
      var q = (el.value || '').trim();
      if (q.length < 1) {
        fill([]);
        return;
      }
      clearTimeout(timer);
      timer = setTimeout(function () {
        if (q === lastQ) return;
        lastQ = q;
        fetch('/api/users/suggest?q=' + encodeURIComponent(q), {
          headers: { 'Accept': 'application/json' },
          credentials: 'same-origin'
        })
          .then(function (r) { return r.ok ? r.json() : []; })
          .then(fill)
          .catch(function () { fill([]); });
      }, 200);
    });
  })();

  /* Machine token create: scope chips (ot-taginput) + restrict toggle */
  (function () {
    function tagsOf(el) {
      if (!el) return [];
      try {
        var v = el.value;
        if (Array.isArray(v)) return v.map(String).filter(Boolean);
        if (typeof v === 'string' && v) {
          return v.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
        }
      } catch (e) {}
      return [];
    }
    function setTags(el, arr) {
      if (!el) return;
      try { el.value = arr; } catch (e) {}
    }
    function addTag(el, tag) {
      tag = (tag || '').trim();
      if (!tag) return;
      var cur = tagsOf(el);
      if (cur.indexOf(tag) >= 0) return;
      cur.push(tag);
      setTags(el, cur);
    }
    function bindForm(form) {
      if (!form || form._scopeBound) return;
      form._scopeBound = true;
      var toggle = form.querySelector('[data-scope-toggle]');
      var body = form.querySelector('[data-scope-body]');
      var openMsg = form.querySelector('[data-scope-open-msg]');
      var tags = form.querySelector('[data-scope-tags]');
      var hidden = form.querySelector('[data-scope-hidden]');
      var roleSel = form.querySelector('[data-token-role]');
      var writeWarn = form.querySelector('[data-token-write-warn]');
      var emptyErr = form.querySelector('[data-scope-empty-err]');
      function syncScope() {
        var on = toggle && toggle.checked;
        if (body) body.hidden = !on;
        if (openMsg) openMsg.hidden = !!on;
        if (emptyErr) emptyErr.hidden = true;
        if (!on && tags) setTags(tags, []);
      }
      function syncRole() {
        if (!writeWarn || !roleSel) return;
        writeWarn.hidden = roleSel.value !== 'service-write';
      }
      if (toggle) toggle.addEventListener('change', syncScope);
      if (roleSel) roleSel.addEventListener('change', syncRole);
      form.querySelectorAll('[data-scope-preset]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          if (toggle && !toggle.checked) {
            toggle.checked = true;
            syncScope();
          }
          addTag(tags, btn.getAttribute('data-scope-preset'));
        });
      });
      form.addEventListener('submit', function (e) {
        if (hidden) {
          var list = (toggle && toggle.checked) ? tagsOf(tags) : ['*'];
          if (toggle && toggle.checked && list.length === 0) {
            e.preventDefault();
            if (emptyErr) emptyErr.hidden = false;
            return;
          }
          hidden.value = list.join('\n');
        }
      });
      syncScope();
      syncRole();
    }
    function boot(root) {
      (root || document).querySelectorAll('form[data-scope-form]').forEach(bindForm);
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { boot(document); });
    } else {
      boot(document);
    }
    document.addEventListener('htmx:afterSwap', function (e) {
      boot(e && e.target ? e.target : document);
    });
  })();

  /* Unsaved-changes guard: warn before leaving a page with dirty forms. */
  (function () {
    function snapshot(form) {
      return new FormData(form);
    }
    function same(a, b) {
      if (a.length !== b.length) return false;
      var ak = Array.from(a.keys()).sort().join('|');
      var bk = Array.from(b.keys()).sort().join('|');
      if (ak !== bk) return false;
      for (var k of ak.split('|')) {
        var av = a.getAll(k).join('\u0000');
        var bv = b.getAll(k).join('\u0000');
        if (av !== bv) return false;
      }
      return true;
    }
    function scan(root) {
      (root || document).querySelectorAll('form[data-dirty-guard]').forEach(function (f) {
        if (!f._clean) f._clean = snapshot(f);
        f.addEventListener('input', function () { f._dirty = !same(f._clean, snapshot(f)); });
      });
    }
    scan(document);
    document.addEventListener('htmx:afterSwap', function (e) {
      scan(e && e.target ? e.target : document);
    });
    window.addEventListener('beforeunload', function (e) {
      var dirty = null;
      document.querySelectorAll('form[data-dirty-guard]').forEach(function (f) {
        if (f._dirty) dirty = f;
      });
      if (dirty) { e.preventDefault(); e.returnValue = ''; }
    });
    /* Intercept sidebar subnav links when a guarded form is dirty */
    document.addEventListener('click', function (e) {
      var link = e.target.closest && e.target.closest('.side-nav-link');
      if (!link) return;
      var dirty = null;
      document.querySelectorAll('form[data-dirty-guard]').forEach(function (f) {
        if (f._dirty) dirty = f;
      });
      if (dirty && !window.confirm('You have unsaved changes. Leave anyway?')) {
        e.preventDefault();
      }
    }, true);
  })();

  /* Dim search/filter forms immediately on submit (full-page GET). */
  document.addEventListener('submit', function (e) {
    var f = e.target && e.target.closest ? e.target.closest('form[method="get"]') : null;
    if (f) f.classList.add('submitting');
  }, true);

  (function () {
    var clearTimer = null;
    var lastCopied = null;
    /* Prefer oat.ink toast; fall back to console if script not loaded yet */
    function toast(msg, title, opts) {
      if (window.ot && typeof ot.toast === 'function') {
        ot.toast(String(msg || ''), title || '', opts || { duration: 2200 });
        return;
      }
      if (window.console) console.info(msg);
    }
    window.ssToast = toast;
    document.body.addEventListener('htmx:responseError', function () {
      toast('The action failed. Please try again.', 'Error', { duration: 5000 });
    });
    document.body.addEventListener('htmx:sendError', function () {
      toast('The server could not be reached. Please try again.', 'Error', { duration: 5000 });
    });
    document.body.addEventListener('htmx:afterRequest', function (e) {
      var detail = e.detail || {};
      var request = detail.requestConfig || {};
      if (request.verb === 'POST' && detail.successful && detail.elt && detail.elt.dataset.toastSuccess) {
        toast(detail.elt.dataset.toastSuccess, 'Done');
      }
    });
    function readCopyText(el, attrText) {
      if (attrText) return attrText;
      if (!el) return '';
      // Prefer form value for inputs/textareas; PRE/DIV use text content.
      var tag = (el.tagName || '').toUpperCase();
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
        return el.value || '';
      }
      return (el.innerText != null ? el.innerText : el.textContent) || '';
    }
    function fallbackCopy(text, el) {
      // Input/textarea can select in place; PRE/structured views need a temp field.
      if (el && typeof el.select === 'function' && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
        try {
          el.focus();
          el.select();
          if (el.setSelectionRange) el.setSelectionRange(0, (el.value || '').length);
          if (document.execCommand('copy')) return true;
        } catch (err) { /* fall through */ }
      }
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
      document.body.removeChild(ta);
      return ok;
    }
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('.copy-btn');
      if (!btn) return;
      e.preventDefault();
      var id = btn.getAttribute('data-copy-target');
      var el = id ? document.getElementById(id) : null;
      var text = readCopyText(el, btn.getAttribute('data-copy-text') || '');
      if (!text) return;
      var secs = parseInt(btn.getAttribute('data-clear-seconds') || '30', 10);
      function done() {
        toast('Copied to clipboard');
        lastCopied = text;
        if (clearTimer) clearTimeout(clearTimer);
        if (secs > 0 && navigator.clipboard && navigator.clipboard.writeText) {
          clearTimer = setTimeout(function () {
            navigator.clipboard.readText().then(function (cur) {
              if (cur === lastCopied) {
                return navigator.clipboard.writeText('');
              }
            }).catch(function () {});
            clearTimer = null;
          }, secs * 1000);
        }
      }
      // Clipboard API often unavailable on HTTP / non-secure contexts; always
      // fall back so certificate/ssh PRE blocks still copy.
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {
          if (fallbackCopy(text, el)) done();
        });
      } else if (fallbackCopy(text, el)) {
        done();
      }
    });
    /* Grant window countdown on Reveal controls */
    function formatGrantRemain(ms) {
      if (ms <= 0) return 'expired';
      var s = Math.floor(ms / 1000);
      var m = Math.floor(s / 60);
      s = s % 60;
      if (m >= 60) {
        var h = Math.floor(m / 60);
        m = m % 60;
        return h + 'h ' + m + 'm';
      }
      return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
    }
    function tickGrantCountdowns(root) {
      root = root || document;
      var nodes = root.querySelectorAll
        ? root.querySelectorAll('[data-grant-until]')
        : [];
      var any = nodes.length > 0;
      nodes.forEach(function (el) {
        var until = el.getAttribute('data-grant-until');
        if (!until) return;
        var t = Date.parse(until);
        if (isNaN(t)) return;
        var label = formatGrantRemain(t - Date.now());
        if (el.classList && el.classList.contains('grant-countdown')) {
          el.textContent = '(' + label + ')';
        } else {
          var span = el.querySelector('.grant-countdown');
          if (span) span.textContent = '(' + label + ')';
        }
      });
      /* Auto-hide countdown note (revealed secret rows) */
      var hides = root.querySelectorAll ? root.querySelectorAll('[data-hide-until]') : [];
      if (hides.length > 0) any = true;
      hides.forEach(function (el) {
        var until = el.getAttribute('data-hide-until');
        if (!until) return;
        var t = Date.parse(until);
        if (isNaN(t)) return;
        var s = Math.max(0, Math.ceil((t - Date.now()) / 1000));
        var count = el.querySelector('.auto-hide-count');
        if (count) count.textContent = s + 's';
      });
      return any;
    }
    var countdownTimer = null;
    function startCountdownTimer() {
      if (countdownTimer) return;
      countdownTimer = setInterval(function () {
        if (!tickGrantCountdowns(document)) {
          clearInterval(countdownTimer);
          countdownTimer = null;
        }
      }, 1000);
    }
    document.addEventListener('DOMContentLoaded', function () {
      tickGrantCountdowns(document);
      startCountdownTimer();
    });
    document.body.addEventListener('htmx:afterSwap', function (e) {
      tickGrantCountdowns(e.target || document);
      startCountdownTimer();
    });

    /* Auto-hide revealed secrets after N seconds */
    var hideTimers = {};
    function scheduleAutoHide(wrap) {
      if (!wrap || !wrap.getAttribute) return;
      var secs = parseInt(wrap.getAttribute('data-auto-hide') || '0', 10);
      if (!(secs > 0)) return;
      var sid = wrap.getAttribute('data-secret-id') || '';
      var key = sid || String(Math.random());
      if (hideTimers[key]) clearTimeout(hideTimers[key]);
      /* Disclose the auto-hide so users aren't surprised when it re-masks. */
      var head = wrap.querySelector('.reveal-head') || wrap;
      var note = head.querySelector('.auto-hide-note');
      if (!note && secs > 0) {
        note = document.createElement('span');
        note.className = 'auto-hide-note';
        note.innerHTML =
          '<span class="auto-hide-label">Auto-hides in</span> <span class="auto-hide-count"></span>';
        head.appendChild(note);
      }
      if (note) {
        note.setAttribute('data-hide-until', new Date(Date.now() + secs * 1000).toISOString());
        var count = note.querySelector('.auto-hide-count');
        if (count) count.textContent = secs + 's';
      }
      hideTimers[key] = setTimeout(function () {
        hideTimers[key] = null;
        var cell = wrap.closest('.secret-cell');
        if (!cell) {
          /* Standalone wrap (e.g. secret full view): mask in place. */
          wrap.querySelectorAll('.secret-value').forEach(function (el) {
            if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
              el.value = '••••••••';
              el.readOnly = true;
            } else {
              el.textContent = '••••••••';
            }
          });
          wrap.querySelectorAll('.copy-btn').forEach(function (b) { b.disabled = true; });
          if (window.ssToast) window.ssToast('Secret hidden — reload to reveal again');
          return;
        }
        var toggle = document.querySelector(
          '.reveal-toggle[hx-target="#' + cell.id + '"]'
        );
        if (!toggle) {
          /* OOB id pattern */
          var cid = cell.id || '';
          var tid = cid.replace(/^reveal-/, 'reveal-toggle-');
          toggle = document.getElementById(tid);
        }
        if (toggle && toggle.getAttribute('hx-get') && toggle.textContent.trim() === 'Hide') {
          if (window.htmx) {
            htmx.ajax('GET', toggle.getAttribute('hx-get'), {
              target: '#' + cell.id,
              swap: 'innerHTML'
            });
          } else {
            toggle.click();
          }
          if (window.ssToast) window.ssToast('Secret auto-hidden');
        }
      }, secs * 1000);
    }
    document.addEventListener('htmx:afterSwap', function (e) {
      var root = (e && e.detail && e.detail.target) ? e.detail.target : document;
      root.querySelectorAll && root.querySelectorAll('.reveal-wrap[data-auto-hide]').forEach(scheduleAutoHide);
      if (root.classList && root.classList.contains('reveal-wrap')) {
        scheduleAutoHide(root);
      }
      /* Also scan for wraps just inserted */
      if (root.querySelector) {
        var w = root.querySelector('.reveal-wrap[data-auto-hide]');
        if (w) scheduleAutoHide(w);
      }
    });
    /* Dialog open/close + menu navigation (commandfor is not widely available) */
    function oatOpenDialog(dlg) {
      if (!dlg) return;
      if (typeof dlg.showModal === 'function') {
        if (!dlg.open) dlg.showModal();
      } else {
        dlg.setAttribute('open', '');
      }
      var focusEl = dlg.querySelector('input:not([type=hidden]), button:not([data-close-dialog])');
      if (focusEl && focusEl.focus) setTimeout(function () { focusEl.focus(); }, 20);
    }
    function oatCloseDialog(dlg) {
      if (!dlg) return;
      if (typeof dlg.close === 'function') dlg.close();
      else dlg.removeAttribute('open');
      var opener = dlg._opener;
      dlg._opener = null;
      if (opener && opener.isConnected && !opener.disabled) opener.focus();
    }
    window.oatOpenDialog = oatOpenDialog;
    window.oatCloseDialog = oatCloseDialog;
    /* Access approve/deny: disable + relabel the submit button for consistent
       busy feedback (approve buttons live outside their form via form=). */
    function setAccessBusy(form, label) {
      var btn = form.querySelector('button[type="submit"]')
        || (form.id && document.querySelector('button[form="' + form.id + '"]'));
      if (btn) { btn.disabled = true; btn.textContent = label; }
      return true;
    }
    window.setAccessBusy = setAccessBusy;
    /* Shared duplicate-submit guard for non-HTMX, non-dialog POST forms:
       disable the submit button(s) and dim the form while the request is in
       flight so a double-click cannot submit twice. Dialog and HTMX forms
       manage their own request state. Runs in the bubble phase (after inline
       onsubmit) so a canceled confirm (defaultPrevented) leaves the form
       untouched. Disabled controls are omitted from the POST, so copy the
       clicked submitter into a hidden field first (OIDC/LDAP/HSM test vs save). */
    document.addEventListener('submit', function (e) {
      var form = e.target;
      if (e.defaultPrevented || !form || form.tagName !== 'FORM') return;
      var method = (form.getAttribute('method') || '').toLowerCase();
      if (method !== 'post') return;
      if (form.closest('dialog')) return;
      var attrs = form.attributes, i;
      for (i = 0; i < attrs.length; i += 1) {
        if (String(attrs[i].name).indexOf('hx-') === 0) return;
      }
      form.classList.add('submitting');
      var submitter = e.submitter;
      if (submitter && submitter.name) {
        var stamped = document.createElement('input');
        stamped.type = 'hidden';
        stamped.name = submitter.name;
        stamped.value = submitter.value;
        form.appendChild(stamped);
      }
      var sub = form.querySelectorAll('button[type="submit"]');
      for (i = 0; i < sub.length; i += 1) {
        if (!sub[i].disabled) {
          if (sub[i].dataset.busy) sub[i].textContent = sub[i].dataset.busy;
          sub[i].disabled = true;
        }
      }
    });
    document.addEventListener('click', function (e) {
      var openBtn = e.target.closest && e.target.closest('[data-open-dialog]');
      if (openBtn) {
        e.preventDefault();
        var id = openBtn.getAttribute('data-open-dialog');
        var dlg = id ? document.getElementById(id) : null;
        if (dlg) {
          dlg._opener = openBtn;
          oatOpenDialog(dlg);
        }
        return;
      }
      var closeBtn = e.target.closest && e.target.closest('[data-close-dialog]');
      if (closeBtn) {
        e.preventDefault();
        var cid = closeBtn.getAttribute('data-close-dialog');
        var cdlg = cid ? document.getElementById(cid) : closeBtn.closest('dialog');
        if (cdlg) oatCloseDialog(cdlg);
        return;
      }
      var submitBtn = e.target.closest && e.target.closest('[data-submit-form]');
      if (submitBtn) {
        e.preventDefault();
        var form = document.getElementById(submitBtn.getAttribute('data-submit-form'));
        if (!form) return;
        var action = form.querySelector('[data-dialog-action]');
        if (action) {
          action.name = 'action';
          action.value = submitBtn.getAttribute('data-submit-action') || '';
        }
        if (form.requestSubmit) form.requestSubmit();
        else form.submit();
        return;
      }
      /* commandfor polyfill (oat docs) for browsers without Invoker Commands */
      var cmdBtn = e.target.closest && e.target.closest('[commandfor][command]');
      if (cmdBtn) {
        var tid = cmdBtn.getAttribute('commandfor');
        var cmd = cmdBtn.getAttribute('command');
        var tel = tid ? document.getElementById(tid) : null;
        if (!tel) return;
        if (cmd === 'show-modal') {
          e.preventDefault();
          oatOpenDialog(tel);
        } else if (cmd === 'close') {
          e.preventDefault();
          oatCloseDialog(tel);
        }
        return;
      }
      /* Inline toggle: data-toggle-inline="#target-id" hides/shows the target */
      var toggleBtn = e.target.closest && e.target.closest('[data-toggle-inline]');
      if (toggleBtn) {
        e.preventDefault();
        var targetId = toggleBtn.getAttribute('data-toggle-inline');
        var targetEl = targetId ? document.querySelector(targetId) : null;
        if (targetEl) targetEl.hidden = !targetEl.hidden;
        return;
      }
      /* History (and other data-nav) from ot-dropdown menus */
      var navBtn = e.target.closest && e.target.closest('[data-nav]');
      if (navBtn) {
        e.preventDefault();
        var href = navBtn.getAttribute('data-nav');
        if (href) window.location.href = href;
        return;
      }
    });
    document.body.addEventListener('htmx:afterSwap', function (e) {
      var t = e.target;
      if (!t) return;
      /* After access-request POST into a dialog, keep it open */
      if (t.matches && t.matches('dialog') && t.open === false) oatOpenDialog(t);
      if (t.id && String(t.id).indexOf('access-dlg-') === 0) {
        if (!t.open) oatOpenDialog(t);
      }
    });
    /* Bulk multi-select toolbar (secrets list) */
    (function () {
      function boxes() {
        return document.querySelectorAll('input.bulk-secret-cb');
      }
      function selected() {
        return document.querySelectorAll('input.bulk-secret-cb:checked');
      }
      function syncBulkToolbar() {
        var tb = document.getElementById('bulk-toolbar');
        var all = document.getElementById('bulk-select-all');
        var countEl = document.getElementById('bulk-count');
        var apply = document.getElementById('bulk-apply');
        var action = document.getElementById('bulk-action');
        var cbs = boxes();
        var n = selected().length;
        var total = cbs.length;
        if (tb) tb.hidden = total === 0;
        if (countEl) countEl.textContent = String(n);
        if (all) {
          all.checked = total > 0 && n === total;
          all.indeterminate = n > 0 && n < total;
        }
        if (apply) {
          apply.disabled = n === 0 || !action || !action.value;
        }
      }
      document.addEventListener('change', function (e) {
        var t = e.target;
        if (!t) return;
        if (t.id === 'bulk-select-all') {
          var on = t.checked;
          boxes().forEach(function (cb) { cb.checked = on; });
          syncBulkToolbar();
          return;
        }
        if (t.classList && t.classList.contains('bulk-secret-cb')) {
          syncBulkToolbar();
          return;
        }
        if (t.id === 'bulk-action') {
          syncBulkToolbar();
        }
      });
      document.addEventListener('click', function (e) {
        var btn = e.target && e.target.closest && e.target.closest('#bulk-apply');
        if (!btn) return;
        e.preventDefault();
        var form = document.getElementById('bulk-secrets-form')
          || document.getElementById('bulk-trash');
        var action = document.getElementById('bulk-action');
        if (!form || !action || !action.value) return;
        if (!selected().length) {
          if (window.ssToast) window.ssToast('Select at least one secret');
          return;
        }
        var opt = action.options[action.selectedIndex];
        var url = opt && opt.getAttribute('data-url');
        var confirmMsg = opt && opt.getAttribute('data-confirm');
        var n = selected().length;
        if (!url) return;
        if (confirmMsg) {
          confirmMsg = String(confirmMsg).replace(/\{n\}/g, String(n));
          if (!window.confirm(confirmMsg)) return;
        }
        // Single irreversible confirm for permanent bulk delete (count-aware)
        if (action.value === 'purge'
            && !window.confirm(
                 'Permanently delete ' + n + (n === 1 ? ' secret' : ' secrets')
                 + ' forever? This cannot be undone.')) {
          return;
        }
        var field = form.querySelector('#bulk-action-field')
          || document.getElementById('bulk-action-field');
        if (field) field.value = action.value;
        form.setAttribute('action', url);
        form.method = 'post';
        form.submit();
      });
      document.addEventListener('htmx:afterSwap', function () {
        syncBulkToolbar();
      });
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', syncBulkToolbar);
        syncBulkToolbar();
      }
    })();
  })();
