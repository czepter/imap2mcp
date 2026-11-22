/**
 * Turns an HTML mail body into readable plain text for an agent: no markup, styles or scripts; block elements,
 * table rows and list items on their own lines; table cells separated by " | "; links as "text <url>".
 * Best effort on purpose: mail HTML is often broken, so this is a tolerant scanner, not a parser.
 */

const DROP = new Set(["head", "style", "script", "title", "noscript", "template", "svg", "xml"]);
const BLOCK = new Set([
  "address", "article", "aside", "blockquote", "center", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure",
  "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "main", "nav", "ol", "p", "pre", "section",
  "table", "tbody", "thead", "tfoot", "ul", "body", "html",
]);

const NAMED: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ensp: " ", emsp: " ", thinsp: " ", zwnj: "", zwj: "",
  shy: "", euro: "€", pound: "£", yen: "¥", cent: "¢", copy: "©", reg: "®", trade: "™", deg: "°", plusmn: "±",
  times: "×", divide: "÷", middot: "·", bull: "•", hellip: "…", ndash: "–", mdash: "—", lsquo: "‘", rsquo: "’",
  sbquo: "‚", ldquo: "“", rdquo: "”", bdquo: "„", laquo: "«", raquo: "»", sect: "§", para: "¶", micro: "µ",
  auml: "ä", ouml: "ö", uuml: "ü", Auml: "Ä", Ouml: "Ö", Uuml: "Ü", szlig: "ß", eacute: "é", egrave: "è",
  agrave: "à", aacute: "á", ccedil: "ç", ntilde: "ñ", oslash: "ø", aring: "å", iexcl: "¡", iquest: "¿",
  frac12: "½", frac14: "¼", frac34: "¾", sup2: "²", sup3: "³", larr: "←", rarr: "→", uarr: "↑", darr: "↓",
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]*);?/gi, (m, e: string) => {
    if (e[0] === "#") {
      const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (n === 160) return " ";
      return Number.isFinite(n) && n > 0 && n <= 0x10ffff && (n < 0xd800 || n > 0xdfff) ? String.fromCodePoint(n) : m;
    }
    return NAMED[e] ?? NAMED[e.toLowerCase()] ?? m;
  });
}

function attr(attrs: string, name: string): string | undefined {
  const m = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(attrs);
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3] ?? "").trim() : undefined;
}

export function htmlToText(html: string): string {
  let out = "";
  let pre = 0;
  const links: { href: string; start: number }[] = [];
  const nl = (n = 1) => {
    out = out.replace(/[ \t]+$/, "");
    const have = /\n*$/.exec(out)![0].length;
    if (out.length && have < n) out += "\n".repeat(n - have);
  };
  const text = (t: string) => {
    let s = decodeEntities(t);
    if (!pre) {
      s = s.replace(/[\s ]+/g, " ");
      if (s.startsWith(" ") && (out === "" || /[\s|]$/.test(out))) s = s.slice(1);
    }
    out += s;
  };

  const re = /<!--[\s\S]*?(?:-->|$)|<!\[CDATA\[[\s\S]*?(?:\]\]>|$)|<![^>]*>|<\?[^>]*>|<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
  let last = 0;
  for (let m = re.exec(html); m; m = re.exec(html)) {
    if (m.index > last) text(html.slice(last, m.index));
    last = re.lastIndex;
    if (m[2] === undefined) continue; // comment, doctype, CDATA, processing instruction
    const close = m[1] === "/";
    const tag = m[2].toLowerCase();
    const attrs = m[3] ?? "";

    if (!close && DROP.has(tag) && !/\/\s*$/.test(attrs)) {
      const end = new RegExp(`</${tag}\\s*>`, "ig");
      end.lastIndex = last;
      const e = end.exec(html);
      last = e ? end.lastIndex : html.length;
      re.lastIndex = last;
      continue;
    }
    if (tag === "br") { if (pre) out += "\n"; else { out = out.replace(/ +$/, ""); out += "\n"; } continue; }
    if (tag === "hr") { nl(); out += "---"; nl(); continue; }
    if (tag === "img") { continue; }
    if (tag === "pre") { nl(2); pre += close ? -1 : 1; if (pre < 0) pre = 0; continue; }
    if (tag === "li") { nl(); if (!close) out += "- "; continue; }
    if (tag === "tr") { nl(); continue; }
    if (tag === "td" || tag === "th") {
      const t = out.replace(/ +$/, "");
      if (!close && !/(^|\n|\|)$/.test(t)) out = t + " | ";
      continue;
    }
    if (tag === "a") {
      if (!close) {
        const href = attr(attrs, "href");
        if (href && /^https?:\/\//i.test(href)) links.push({ href, start: out.length });
        else links.push({ href: "", start: out.length });
      } else {
        const l = links.pop();
        if (l?.href) {
          const label = out.slice(l.start).trim();
          if (label !== l.href && label.replace(/^https?:\/\//i, "") !== l.href.replace(/^https?:\/\//i, "").replace(/\/$/, "")) {
            out = out.replace(/ +$/, "") + (label ? " " : "") + `<${l.href}>`;
          }
        }
      }
      continue;
    }
    if (/^h[1-6]$/.test(tag) || tag === "p" || tag === "blockquote" || tag === "table") { nl(2); continue; }
    if (BLOCK.has(tag)) { nl(); continue; }
  }
  if (last < html.length) text(html.slice(last));

  return out
    .split("\n")
    .map((l) => l.replace(/[ \t]+$/, "").replace(/^(?: \| )+/, "").replace(/(?: \|)+$/, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
