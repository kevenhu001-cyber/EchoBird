// Tiny inline HTML for the OAuth callback success / error pages.
//
// The browser lands here once the provider redirects after the user clicks
// "Authorize". We keep the page lightweight (no external assets, no
// network calls) because:
//   * the user already has their browser open — no reason to make it block
//     on a CDN before they can close the tab
//   * CSP isolation: if a future Tauri hardening pass sets a strict CSP,
//     inline HTML keeps working
//   * privacy: zero third-party requests, no analytics
//
// The page auto-closes the tab after 5s; if the browser blocks
// window.close() (most do for tabs the user didn't open), the user can
// close it by hand. We also show a clear EchoBird-branded headline so
// the user knows they're done and not stuck on a generic provider page.
//
// CSS lives inline. We pick colors that match EchoBird's dark theme
// (the user is on the desktop app), but flip to a clean white card so
// the page reads well in a normal browser tab too.

/// Rendered when `state` matches AND the provider returned an auth code.
/// The `provider_label` is interpolated so the user can tell which login
/// they just finished (relevant when they have two browser tabs open).
pub fn success_for(provider_label: &str) -> String {
    let escaped = escape(provider_label);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{label} login complete</title>
<style>{style}</style>
</head>
<body>
  <div class="card">
    <div class="check">&#10003;</div>
    <h1>{label} login complete</h1>
    <p>You can close this tab and return to EchoBird.</p>
    <p class="muted">This window will auto-close in <span id="cd">5</span>s.</p>
    <button id="close">Close now</button>
  </div>
<script>
(function(){{
  var n = 5, cd = document.getElementById('cd'), btn = document.getElementById('close');
  var t = setInterval(function(){{ n--; if(cd) cd.textContent = String(n); if(n<=0){{ clearInterval(t); try{{ window.close(); }}catch(_){{}} }} }}, 1000);
  btn.addEventListener('click', function(){{ clearInterval(t); try{{ window.close(); }}catch(_){{}} }});
}})();
</script>
</body>
</html>"#,
        label = escaped,
        style = STYLE
    )
}

/// Rendered when state mismatch / missing code / provider-returned error.
/// We show the message so the user can copy-paste it into a bug report.
pub fn error_for(provider_label: &str, message: &str) -> String {
    let label = escape(provider_label);
    let msg = escape(message);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{label} login failed</title>
<style>{style}</style>
</head>
<body>
  <div class="card error">
    <div class="cross">&#10007;</div>
    <h1>{label} login failed</h1>
    <p class="msg">{msg}</p>
    <p>Close this tab and retry from EchoBird.</p>
  </div>
</body>
</html>"#,
        label = label,
        msg = msg,
        style = STYLE
    )
}

/// Generic /success page used when the callback server isn't bound to a
/// specific provider (e.g. user navigated there manually). Rare in practice
/// but useful when the route handler wants to acknowledge without context.
pub const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>OK</title></head>
<body><h1>OK</h1><p>You can close this tab.</p></body>
</html>"#;

/// Generic /error page.
pub const ERROR_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Error</title></head>
<body><h1>Error</h1><p>Close this tab and retry.</p></body>
</html>"#;

const STYLE: &str = r#"
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       display:flex;justify-content:center;align-items:center;
       min-height:100vh;margin:0;background:#0f1419;color:#e6e6e6}
  .card{background:#1a1f2e;border-radius:12px;padding:36px 48px;
        max-width:480px;text-align:center;
        box-shadow:0 12px 40px rgba(0,0,0,0.4)}
  .check,.cross{width:64px;height:64px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;
                margin:0 auto 18px;font-size:32px;color:#fff}
  .check{background:#10b981}
  .cross{background:#ef4444}
  h1{margin:0 0 12px;font-size:22px;font-weight:600;color:#fff}
  p{margin:8px 0;line-height:1.5;color:#b8bcc8}
  .muted{color:#7d8590;font-size:14px}
  .msg{background:#2a1f1f;border:1px solid #5a2a2a;border-radius:6px;
       padding:10px 14px;font-family:Menlo,Consolas,monospace;
       font-size:13px;color:#fca5a5;word-break:break-word;text-align:left}
  button{margin-top:18px;background:#d97757;color:#fff;border:none;
         border-radius:6px;padding:10px 20px;font-size:14px;
         cursor:pointer;font-weight:500}
  button:hover{background:#c46549}
"#;

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_includes_provider_label() {
        let html = success_for("Claude");
        assert!(html.contains("Claude"));
        assert!(html.contains("login complete"));
        assert!(html.contains("window.close"));
    }

    #[test]
    fn error_includes_message_and_escapes_html() {
        let html = error_for("Codex", "<script>alert(1)</script>");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn escape_handles_ampersands() {
        assert_eq!(escape("AT&T"), "AT&amp;T");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
    }
}
