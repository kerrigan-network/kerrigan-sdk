/** Tiny, dependency-free markdown → HTML renderer.
 *
 *  Scope is deliberately small: what an LLM actually produces in a
 *  chat context. Bold, italic, inline code, fenced code blocks,
 *  headings h1–h3, bullet / numbered lists, links, paragraphs with
 *  `<br>` on single newlines.
 *
 *  Safety model: every user-supplied substring is HTML-escaped BEFORE
 *  any markdown regex runs, and the regexes only produce a handful of
 *  known-safe tags. Raw `<tags>` from the model body are escaped and
 *  rendered as text — they cannot smuggle markup through. Fenced code
 *  contents are placeholder-swapped before escaping so the escape
 *  pass doesn't mangle them, then re-inserted as escaped bodies.
 */

const NUL = '\u0000';  // private placeholder delimiter

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderMarkdown(raw) {
  if (!raw) return '';
  let text = String(raw);

  // 0. Whitespace hygiene — some models emit paragraphs separated by
  //    "blank" lines that actually contain spaces or tabs, so a later
  //    `\n{2,}` split won't see them as paragraph breaks and the
  //    `\n → <br>` step turns them into visible gaps inside a single
  //    `<p>`. Normalise those to true empty lines, collapse runs of
  //    3+ blank lines down to one, and trim outer whitespace.
  text = text
    .replace(/\r\n?/g, '\n')       // CRLF / CR → LF
    .replace(/^[ \t]+$/gm, '')     // spaces-only lines → empty
    .replace(/\n{3,}/g, '\n\n')    // cap runs of blanks at two
    .trim();

  // 1. Pull fenced code blocks out first so the rest of the pipeline
  //    can't corrupt them.
  const codeBlocks = [];
  text = text.replace(/```([a-zA-Z0-9_+-]*)\n?([\s\S]*?)```/g, (_, lang, body) => {
    codeBlocks.push({ lang, body });
    return `${NUL}FENCE${codeBlocks.length - 1}${NUL}`;
  });

  // 2. Escape everything else.
  text = escapeHtml(text);

  // 3. Inline code — run before bold/italic so `*foo*` inside a code
  //    span isn't italicised.
  const inlineCodes = [];
  text = text.replace(/`([^`\n]+)`/g, (_, body) => {
    inlineCodes.push(body);
    return `${NUL}INLINE${inlineCodes.length - 1}${NUL}`;
  });

  // 4. Headings (ATX style, 1–3 levels — all we need for chat output).
  text = text.replace(/^### +(.+)$/gm, '<h3>$1</h3>');
  text = text.replace(/^## +(.+)$/gm,  '<h2>$1</h2>');
  text = text.replace(/^# +(.+)$/gm,   '<h1>$1</h1>');

  // 5. Bold + italic. Bold first so `**foo**` doesn't collapse into `*<em>foo</em>*`.
  text = text.replace(/\*\*([^*\n]+?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/(^|[^\w*])\*([^*\n]+?)\*(?![\w*])/g, '$1<em>$2</em>');
  text = text.replace(/(^|[^\w_])_([^_\n]+?)_(?![\w_])/g, '$1<em>$2</em>');

  // 6. Links. Text and URL are already HTML-escaped.
  text = text.replace(
    /\[([^\]\n]+)\]\(([^)\s]+)\)/g,
    '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>',
  );

  // 7. Lists. Group consecutive matching lines into a <ul> / <ol>.
  text = groupLines(text, /^[-*] +(.+)$/, 'ul');
  text = groupLines(text, /^\d+\. +(.+)$/, 'ol');

  // 7b. GitHub-flavoured tables. A header row of pipes + cells, followed
  //     by a separator row of dashes (optionally wrapped in colons for
  //     alignment), followed by zero-or-more body rows. Cell contents
  //     still have inline formatting (bold/italic/links/code) applied
  //     from the earlier passes — we just carve the structure here.
  text = groupTables(text);

  // 8. Paragraphs — blank-line separated. Skip blocks that already
  //    start with a known block-level tag.
  text = text
    .split(/\n{2,}/)
    .map((chunk) => {
      const c = chunk.trim();
      if (!c) return '';
      if (/^<(h[1-6]|ul|ol|li|pre|blockquote|table|hr|div)/.test(c)) return c;
      return `<p>${c.replace(/\n/g, '<br>')}</p>`;
    })
    .join('');

  // 9. Swap inline code + fence placeholders back in, escaping their
  //    bodies at rehydration time.
  text = text.replace(new RegExp(`${NUL}INLINE(\\d+)${NUL}`, 'g'), (_, i) =>
    `<code>${escapeHtml(inlineCodes[Number(i)])}</code>`);
  text = text.replace(new RegExp(`${NUL}FENCE(\\d+)${NUL}`, 'g'), (_, i) => {
    const { lang, body } = codeBlocks[Number(i)];
    const langAttr = lang ? ` data-lang="${escapeHtml(lang)}"` : '';
    return `<pre class="md-pre"><code${langAttr}>${escapeHtml(body.replace(/\n$/, ''))}</code></pre>`;
  });

  return text;
}

/** Collapse runs of lines matching `itemRe` into a single `<tag>…</tag>`. */
function groupLines(text, itemRe, tag) {
  const lines = text.split('\n');
  const out = [];
  let buf = [];
  const flush = () => {
    if (!buf.length) return;
    out.push(`<${tag}>` + buf.map((i) => `<li>${i}</li>`).join('') + `</${tag}>`);
    buf = [];
  };
  for (const line of lines) {
    const m = line.match(itemRe);
    if (m) buf.push(m[1]);
    else { flush(); out.push(line); }
  }
  flush();
  return out.join('\n');
}

// GFM table separator: pipes + at least one cell of `---` or `:---` etc.
//   |:---|:---:|---:|    |----|----|
// Ignores the `-{3,}` minimum some renderers require; 1+ dash is enough.
const TABLE_SEP_RE = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$/;
const TABLE_ROW_RE = /^\s*\|.*\|\s*$/;

function splitTableRow(row) {
  let s = row.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|'))   s = s.slice(0, -1);
  return s.split('|').map((c) => c.trim());
}

function parseTableAlignments(sep) {
  return splitTableRow(sep).map((cell) => {
    const l = cell.startsWith(':');
    const r = cell.endsWith(':');
    if (l && r) return 'center';
    if (r)      return 'right';
    if (l)      return 'left';
    return null;
  });
}

/** Walk `text` line-by-line. When we find a `| … | … |` line followed by
 *  a separator-row of dashes, collect the table and emit one `<table>`
 *  element in place. Non-table lines pass through untouched. */
function groupTables(text) {
  const lines = text.split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const header = lines[i];
    const sep = lines[i + 1];
    const isTable = header != null && sep != null
      && TABLE_ROW_RE.test(header) && TABLE_SEP_RE.test(sep);
    if (!isTable) {
      out.push(header);
      i++;
      continue;
    }
    const headerCells = splitTableRow(header);
    const aligns = parseTableAlignments(sep);
    const bodyRows = [];
    let j = i + 2;
    while (j < lines.length && TABLE_ROW_RE.test(lines[j])) {
      bodyRows.push(splitTableRow(lines[j]));
      j++;
    }

    const styleFor = (col) =>
      aligns[col] ? ` style="text-align:${aligns[col]}"` : '';
    const thead = '<thead><tr>'
      + headerCells.map((c, k) => `<th${styleFor(k)}>${c}</th>`).join('')
      + '</tr></thead>';
    const tbody = '<tbody>'
      + bodyRows.map((row) =>
          '<tr>' + row.map((c, k) => `<td${styleFor(k)}>${c}</td>`).join('') + '</tr>'
        ).join('')
      + '</tbody>';
    // Wrapping the table lets the outer div own horizontal overflow
    // without fighting the `<table>` element's own layout rules. On
    // narrow screens the table keeps its natural cell widths and the
    // wrapper scrolls sideways rather than crushing columns.
    out.push(
      `<div class="md-table-wrap"><table class="md-table">${thead}${tbody}</table></div>`
    );
    i = j;
  }
  return out.join('\n');
}

/** Pull `<think>…</think>` blocks out of a response. Returns the body
 *  with thoughts stripped plus the list of thought strings. The model
 *  sometimes opens a `<think>` and never closes it (cut off mid-stream);
 *  treat the unterminated tail as one big thought block. */
export function splitThinking(raw) {
  if (!raw) return { thoughts: [], body: '' };
  const thoughts = [];
  let body = String(raw);

  body = body.replace(/<think>([\s\S]*?)<\/think>/gi, (_, t) => {
    thoughts.push(t.trim());
    return '';
  });

  // Unterminated `<think>` → take everything after as the thought.
  const openIdx = body.search(/<think>/i);
  if (openIdx !== -1) {
    thoughts.push(body.slice(openIdx + 7).trim());
    body = body.slice(0, openIdx);
  }

  return { thoughts, body: body.trim() };
}
