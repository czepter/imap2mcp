import { describe, it, expect } from "vitest";
import { htmlToText, decodeEntities } from "../../server/core/mcp/htmlToText.js";

describe("htmlToText", () => {
  it("drops head, style, script and comments", () => {
    const html = `<!DOCTYPE html><html><head><title>T</title><style>p{color:red}</style></head>
      <body><!-- tracking --><script>alert(1)</script><p>Hallo</p></body></html>`;
    expect(htmlToText(html)).toBe("Hallo");
  });

  it("puts block elements and <br> on their own lines and collapses whitespace", () => {
    expect(htmlToText("<div>Eins\n   zwei</div><p>drei<br>vier</p><h1>Fünf</h1>")).toBe("Eins zwei\n\ndrei\nvier\n\nFünf");
  });

  it("renders table rows as lines and cells separated by pipes", () => {
    const html = `<table><tr><th>Posten</th><th>Betrag</th></tr>
      <tr><td>Strom</td><td></td><td>123,45&nbsp;&euro;</td></tr></table>`;
    expect(htmlToText(html)).toBe("Posten | Betrag\nStrom | 123,45 €");
  });

  it("keeps http links as <url> after the label, skips duplicates and non-http links", () => {
    expect(htmlToText('<a href="https://x.example/r?a=1&amp;b=2">Rechnung</a>')).toBe("Rechnung <https://x.example/r?a=1&b=2>");
    expect(htmlToText('<a href="https://x.example">https://x.example</a>')).toBe("https://x.example");
    expect(htmlToText('<a href="mailto:a@b.example">schreiben</a>')).toBe("schreiben");
  });

  it("lists items and keeps <pre> whitespace", () => {
    expect(htmlToText("<ul><li>a</li><li>b</li></ul><pre>x  y\n  z</pre>")).toBe("- a\n- b\n\nx  y\n  z");
  });

  it("decodes named and numeric entities", () => {
    expect(decodeEntities("&auml;&#246;&#xFC; &lt;&gt; &amp;amp; &unknown;")).toBe("äöü <> &amp; &unknown;");
  });

  it("tolerates broken markup", () => {
    expect(htmlToText("<p>offen <b>fett<p>weiter <style>nie zu")).toBe("offen fett\n\nweiter");
  });
});
