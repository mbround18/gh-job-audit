//! Data-driven email template: a JSON `Report` in, branded HTML + plain text out.
//!
//! ```json
//! { "brand": {"name": "mbround18", "avatar_url": "...", "accent": "#3b82f6"},   // optional: auto from GitHub
//!   "title": "GitHub, this week", "subtitle": "Sep 20 - 27", "preheader": "3 things need you",
//!   "stats": [{"label": "Open alerts", "value": "12", "delta": "+3", "tone": "bad"}],
//!   "sections": [{"group": "Security", "title": "Dependabot", "note": "...", "tone": "high",
//!                 "rows": [{"label": "owner/repo", "url": "https://...", "detail": "...", "badge": "high"}]}],
//!   "footer": "..." }
//! ```
//! Tones: critical | high | medium | low | good | neutral (also bad/warn for stats).
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Brand {
    #[serde(default)]
    pub name: String,
    pub tagline: Option<String>,
    pub avatar_url: Option<String>,
    pub url: Option<String>,
    /// `#rrggbb`; derived from the name when absent.
    pub accent: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Stat {
    pub label: String,
    pub value: String,
    pub delta: Option<String>,
    pub tone: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Row {
    pub label: String,
    pub url: Option<String>,
    pub detail: Option<String>,
    pub badge: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Section {
    pub group: Option<String>,
    pub title: String,
    pub note: Option<String>,
    pub tone: Option<String>,
    #[serde(default)]
    pub rows: Vec<Row>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Report {
    pub brand: Option<Brand>,
    pub title: String,
    pub subtitle: Option<String>,
    pub preheader: Option<String>,
    pub intro: Option<String>,
    #[serde(default)]
    pub stats: Vec<Stat>,
    #[serde(default)]
    pub sections: Vec<Section>,
    pub footer: Option<String>,
}

impl Brand {
    /// Profile of a user or org: avatar, display name, bio and link. Falls back to just the login
    /// (and a derived accent) if the API gives nothing. `BRAND_ACCENT` overrides the colour.
    pub async fn from_github(gh: &gh_core::Client, login: &str) -> Brand {
        let mut p = gh.json_opt(&format!("/users/{login}")).await.ok().flatten();
        if p.is_none() {
            p = gh.json_opt(&format!("/orgs/{login}")).await.ok().flatten();
        }
        let g = |k: &str| {
            p.as_ref()
                .and_then(|v| v[k].as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        };
        Brand {
            name: g("name").unwrap_or_else(|| login.to_string()),
            tagline: g("bio").or_else(|| g("description")),
            avatar_url: g("avatar_url")
                .map(|u| format!("{u}{}s=112", if u.contains('?') { "&" } else { "?" })),
            url: g("html_url").or_else(|| Some(format!("https://github.com/{login}"))),
            accent: std::env::var("BRAND_ACCENT")
                .ok()
                .filter(|c| valid_hex(c))
                .or_else(|| Some(accent_for(login))),
        }
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn safe_url(u: &str) -> Option<String> {
    (u.starts_with("https://") || u.starts_with("http://")).then(|| esc(u))
}

/// Deterministic accent from a name so each user/org gets a stable colour with no config.
pub fn accent_for(name: &str) -> String {
    let h = name
        .bytes()
        .fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32))
        % 360;
    let (s, l) = (0.62f32, 0.46f32);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h as f32 / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = match h / 60 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let f = |v: f32| ((v + m) * 255.0).round() as u8;
    format!("#{:02x}{:02x}{:02x}", f(r), f(g), f(b))
}

fn valid_hex(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit())
}

/// (border/badge colour, soft background)
fn tone(t: Option<&str>) -> (&'static str, &'static str) {
    match t.unwrap_or("neutral") {
        "critical" | "bad" => ("#dc2626", "#fef2f2"),
        "high" | "warn" => ("#ea580c", "#fff7ed"),
        "medium" => ("#ca8a04", "#fefce8"),
        "good" => ("#16a34a", "#f0fdf4"),
        "low" => ("#6b7280", "#f3f4f6"),
        _ => ("#6b7280", "#f3f4f6"),
    }
}

/// Gmail clips messages past ~102 KB of HTML, so rows are trimmed (largest sections first)
/// until the document fits; the plain-text part keeps every row.
const HTML_BUDGET: usize = 95_000;

impl Report {
    pub fn render(&self) -> (String, String) {
        let mut r = self.clone();
        let mut html = r.html();
        while html.len() > HTML_BUDGET {
            let Some(big) = r
                .sections
                .iter_mut()
                .filter(|s| s.rows.len() > 5)
                .max_by_key(|s| s.rows.len())
            else {
                break;
            };
            let keep = big.rows.len() * 3 / 4;
            big.rows.truncate(keep);
            html = r.html_with(&self.sections);
        }
        (html, self.text())
    }

    fn html(&self) -> String {
        self.html_with(&self.sections)
    }

    fn html_with(&self, full: &[Section]) -> String {
        let brand = self.brand.clone().unwrap_or_default();
        let accent = brand
            .accent
            .as_deref()
            .filter(|c| valid_hex(c))
            .map(String::from)
            .unwrap_or_else(|| accent_for(&brand.name));
        let mut h = String::with_capacity(32_000);
        h.push_str(&format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta name=\"color-scheme\" content=\"light\"><title>{}</title></head>\
             <body style=\"margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827\">",
            esc(&self.title)
        ));
        if let Some(p) = &self.preheader {
            h.push_str(&format!(
                "<div style=\"display:none;max-height:0;overflow:hidden;opacity:0\">{}</div>",
                esc(p)
            ));
        }
        h.push_str("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr><td align=\"center\" style=\"padding:24px 12px\">");
        h.push_str("<table role=\"presentation\" width=\"640\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:640px;width:100%;background:#fff;border-radius:14px;overflow:hidden\">");
        // header
        h.push_str(&format!("<tr><td style=\"background:{accent};padding:26px 28px\"><table role=\"presentation\" width=\"100%\"><tr>"));
        if let Some(a) = brand.avatar_url.as_deref().and_then(safe_url) {
            h.push_str(&format!("<td width=\"64\" valign=\"middle\"><img src=\"{a}\" width=\"56\" height=\"56\" alt=\"\" style=\"border-radius:50%;border:2px solid rgba(255,255,255,.7);display:block\"></td>"));
        }
        let name = match brand.url.as_deref().and_then(safe_url) {
            Some(u) => format!(
                "<a href=\"{u}\" style=\"color:#fff;text-decoration:none\">{}</a>",
                esc(&brand.name)
            ),
            None => esc(&brand.name),
        };
        h.push_str(&format!("<td valign=\"middle\" style=\"color:#fff\"><div style=\"font-size:13px;opacity:.85;letter-spacing:.04em;text-transform:uppercase\">{name}</div><div style=\"font-size:24px;font-weight:700;line-height:1.25\">{}</div>", esc(&self.title)));
        if let Some(sub) = &self.subtitle {
            h.push_str(&format!(
                "<div style=\"font-size:13px;opacity:.85;margin-top:2px\">{}</div>",
                esc(sub)
            ));
        }
        h.push_str("</td></tr></table></td></tr>");
        h.push_str("<tr><td style=\"padding:22px 28px 8px\">");
        if let Some(i) = &self.intro {
            h.push_str(&format!(
                "<p style=\"margin:0 0 16px;font-size:15px;line-height:1.55;color:#374151\">{}</p>",
                esc(i)
            ));
        }
        // stat cards, three per row
        if !self.stats.is_empty() {
            h.push_str(
                "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"6\">",
            );
            for chunk in self.stats.chunks(3) {
                h.push_str("<tr>");
                for st in chunk {
                    let (c, bg) = tone(st.tone.as_deref());
                    h.push_str(&format!(
                        "<td width=\"33%\" valign=\"top\" style=\"background:{bg};border-radius:10px;padding:12px 14px\"><div style=\"font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em\">{}</div><div style=\"font-size:24px;font-weight:700;color:{c}\">{}</div>",
                        esc(&st.label), esc(&st.value)
                    ));
                    if let Some(d) = &st.delta {
                        h.push_str(&format!(
                            "<div style=\"font-size:12px;color:#6b7280\">{}</div>",
                            esc(d)
                        ));
                    }
                    h.push_str("</td>");
                }
                for _ in chunk.len()..3 {
                    h.push_str("<td></td>");
                }
                h.push_str("</tr>");
            }
            h.push_str("</table>");
        }
        // sections, grouped in first-seen order
        let mut last_group: Option<&str> = None;
        for sec in &self.sections {
            let total = full
                .iter()
                .find(|f| f.title == sec.title)
                .map(|f| f.rows.len())
                .unwrap_or(sec.rows.len());
            if sec.group.as_deref() != last_group {
                if let Some(g) = &sec.group {
                    h.push_str(&format!("<h2 style=\"margin:26px 0 4px;font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:{accent}\">{}</h2><div style=\"height:2px;background:{accent};opacity:.25;margin-bottom:10px\"></div>", esc(g)));
                }
                last_group = sec.group.as_deref();
            }
            let (c, bg) = tone(sec.tone.as_deref());
            h.push_str(&format!(
                "<div style=\"border-left:4px solid {c};background:{bg};border-radius:0 8px 8px 0;padding:10px 14px;margin:10px 0 4px\"><div style=\"font-size:15px;font-weight:600\">{} <span style=\"color:#6b7280;font-weight:400\">({total})</span></div>",
                esc(&sec.title)
            ));
            if let Some(n) = &sec.note {
                h.push_str(&format!(
                    "<div style=\"font-size:12px;color:#6b7280;margin-top:2px\">{}</div>",
                    esc(n)
                ));
            }
            h.push_str("</div>");
            for row in &sec.rows {
                let label = match row.url.as_deref().and_then(safe_url) {
                    Some(u) => format!(
                        "<a href=\"{u}\" style=\"color:#1d4ed8;text-decoration:none\">{}</a>",
                        esc(&row.label)
                    ),
                    None => esc(&row.label),
                };
                let badge = row.badge.as_deref().map(|b| {
                    let (bc, _) = tone(Some(b));
                    format!("<span style=\"display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;color:#fff;background:{bc};border-radius:4px;padding:1px 6px;margin-right:6px\">{}</span>", esc(b))
                });
                h.push_str(&format!(
                    "<div style=\"font-size:13px;line-height:1.45;padding:5px 14px;border-bottom:1px solid #f3f4f6\">{}{label}<span style=\"color:#4b5563\"> {}</span></div>",
                    badge.unwrap_or_default(), esc(row.detail.as_deref().unwrap_or(""))
                ));
            }
            if total > sec.rows.len() {
                h.push_str(&format!("<div style=\"font-size:12px;color:#6b7280;padding:6px 14px\">&hellip; and {} more (full list in the plain-text version)</div>", total - sec.rows.len()));
            }
        }
        h.push_str("</td></tr>");
        h.push_str(&format!(
            "<tr><td style=\"padding:20px 28px 26px;font-size:12px;color:#9ca3af\">{}</td></tr></table></td></tr></table></body></html>",
            esc(self.footer.as_deref().unwrap_or("Sent by gh-job-audit. Read-only checks; nothing here changed your repos."))
        ));
        h
    }

    pub fn text(&self) -> String {
        let name = self.brand.as_ref().map(|b| b.name.as_str()).unwrap_or("");
        let mut t = format!(
            "{}{}{}\n",
            name,
            if name.is_empty() { "" } else { " - " },
            self.title
        );
        if let Some(s) = &self.subtitle {
            t.push_str(&format!("{s}\n"));
        }
        if let Some(i) = &self.intro {
            t.push_str(&format!("\n{i}\n"));
        }
        if !self.stats.is_empty() {
            t.push('\n');
            for s in &self.stats {
                t.push_str(&format!(
                    "{}: {}{}\n",
                    s.label,
                    s.value,
                    s.delta
                        .as_deref()
                        .map(|d| format!(" ({d})"))
                        .unwrap_or_default()
                ));
            }
        }
        let mut last: Option<&str> = None;
        for sec in &self.sections {
            if sec.group.as_deref() != last {
                if let Some(g) = &sec.group {
                    t.push_str(&format!("\n== {} ==\n", g.to_uppercase()));
                }
                last = sec.group.as_deref();
            }
            t.push_str(&format!("\n{} ({})\n", sec.title, sec.rows.len()));
            for r in &sec.rows {
                t.push_str(&format!(
                    "- {} {} {}\n",
                    r.label,
                    r.detail.as_deref().unwrap_or(""),
                    r.url.as_deref().unwrap_or("")
                ));
            }
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_from_json_and_escapes() {
        let r: Report = serde_json::from_str(
            r##"{"title":"Hi <b>","brand":{"name":"acme","accent":"#123456"},
                 "stats":[{"label":"A","value":"1","tone":"bad"}],
                 "sections":[{"group":"G","title":"S","rows":[{"label":"x","url":"javascript:alert(1)","detail":"<i>","badge":"high"}]}]}"##,
        )
        .unwrap();
        let (html, text) = r.render();
        assert!(html.contains("Hi &lt;b&gt;") && html.contains("#123456"));
        assert!(!html.contains("javascript:") && !html.contains("<i>"));
        assert!(text.contains("== G ==") && text.contains("- x"));
    }

    #[test]
    fn stays_under_budget() {
        let rows = (0..4000)
            .map(|i| Row {
                label: format!("repo/{i}"),
                url: Some("https://x.y/z".into()),
                detail: Some("d".repeat(60)),
                badge: None,
            })
            .collect();
        let r = Report {
            title: "big".into(),
            sections: vec![Section {
                title: "s".into(),
                rows,
                ..Default::default()
            }],
            ..Default::default()
        };
        let (html, text) = r.render();
        assert!(html.len() <= HTML_BUDGET + 2000, "{}", html.len());
        assert!(text.matches("repo/").count() == 4000);
    }

    #[test]
    fn accent_is_stable_hex() {
        assert!(valid_hex(&accent_for("mbround18")) && accent_for("a") == accent_for("a"));
    }
}
