// Lightweight JSON <-> XML converters used by the JSONToXML / XMLToJSON
// transformation policies. These are simplified but functionally real
// (not just cosmetic simulations) - good enough to demonstrate the concept
// during interview practice without pulling in a heavy XML library.

export function jsonToXml(value: any, rootName = "root"): string {
  function build(name: string, val: any): string {
    if (val === null || val === undefined) return `<${name}/>`;
    if (Array.isArray(val)) {
      return val.map((item) => build(name, item)).join("");
    }
    if (typeof val === "object") {
      const inner = Object.keys(val)
        .map((k) => build(k, val[k]))
        .join("");
      return `<${name}>${inner}</${name}>`;
    }
    return `<${name}>${escapeXml(String(val))}</${name}>`;
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n${build(rootName, value)}`;
}

function escapeXml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Very small, dependency-free XML -> JSON parser. Supports simple nested
// elements and repeated sibling tags (converted to arrays). Not a full XML
// spec implementation, but sufficient for simulator payloads.
export function xmlToJson(xml: string): any {
  const cleaned = xml.replace(/<\?xml[^>]*\?>/, "").trim();

  function parseChildren(fragment: string): Array<{ tagName: string; value: any }> {
    const results: Array<{ tagName: string; value: any }> = [];
    let p = 0;
    while (p < fragment.length) {
      while (p < fragment.length && /\s/.test(fragment[p])) p++;
      if (p >= fragment.length || fragment[p] !== "<") break;
      const tagMatch = /^<([a-zA-Z0-9_:-]+)([^>]*)>/.exec(fragment.slice(p));
      if (!tagMatch) break;
      const [full, tagName] = tagMatch;
      p += full.length;
      if (full.endsWith("/>")) {
        results.push({ tagName, value: null });
        continue;
      }
      const closeTag = `</${tagName}>`;
      const closeIdx = fragment.indexOf(closeTag, p);
      const inner = fragment.slice(p, closeIdx === -1 ? fragment.length : closeIdx);
      p = closeIdx === -1 ? fragment.length : closeIdx + closeTag.length;
      if (/^</.test(inner.trim())) {
        const nested = parseChildren(inner);
        const obj: Record<string, any> = {};
        for (const child of nested) {
          if (obj[child.tagName] !== undefined) {
            if (!Array.isArray(obj[child.tagName])) obj[child.tagName] = [obj[child.tagName]];
            obj[child.tagName].push(child.value);
          } else {
            obj[child.tagName] = child.value;
          }
        }
        results.push({ tagName, value: obj });
      } else {
        results.push({ tagName, value: inner.trim() });
      }
    }
    return results;
  }

  const roots = parseChildren(cleaned);
  if (roots.length === 0) return {};
  const result: Record<string, any> = {};
  for (const r of roots) result[r.tagName] = r.value;
  return result;
}
