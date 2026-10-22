// Which documents an account may hold. The server only ever sees ciphertext,
// so this check runs in the browser before encryption: open formats that
// read on any Linux box, plain machine-readable text, and PDF. Microsoft and
// Apple formats are refused by name with a hint to export them first.

export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;

type Rule = { type: string; check: (bytes: Uint8Array) => boolean };

const text = (type: string): Rule => ({ type, check: isText });

const odf = (kind: string): Rule => ({
  type: `application/vnd.oasis.opendocument.${kind}`,
  check: (bytes) => isOpenDocument(bytes, kind),
});

const rules: Record<string, Rule> = {
  pdf: { type: "application/pdf", check: (b) => startsWith(b, [0x25, 0x50, 0x44, 0x46, 0x2d]) },
  png: { type: "image/png", check: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  jpg: { type: "image/jpeg", check: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  jpeg: { type: "image/jpeg", check: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  webp: { type: "image/webp", check: (b) => ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 12) === "WEBP" },
  gif: { type: "image/gif", check: (b) => ascii(b, 0, 4) === "GIF8" },
  odt: odf("text"),
  ods: odf("spreadsheet"),
  odp: odf("presentation"),
  odg: odf("graphics"),
  txt: text("text/plain"),
  md: text("text/markdown"),
  csv: text("text/csv"),
  tsv: text("text/tab-separated-values"),
  json: { type: "application/json", check: (b) => isText(b) && parses(b) },
  xml: text("application/xml"),
  yaml: text("application/yaml"),
  yml: text("application/yaml"),
  toml: text("application/toml"),
  ini: text("text/plain"),
  conf: text("text/plain"),
  log: text("text/plain"),
  pem: text("application/x-pem-file"),
  crt: text("application/x-pem-file"),
  asc: text("application/pgp-keys"),
};

// Formats people will try first. Each gets a specific answer.
const closed = new Set([
  "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "ppt", "pptx", "pptm", "pps", "ppsx",
  "rtf", "msg", "one", "vsd", "vsdx", "pub", "xps", "oxps", "mdb", "accdb", "wps",
  "pages", "numbers", "key", "heic", "heif", "webarchive",
]);

export const ACCEPTED_EXTENSIONS = Object.keys(rules);

// The file picker's filter. Validation below is what actually decides.
export const ACCEPT_ATTRIBUTE = ACCEPTED_EXTENSIONS.map((ext) => `.${ext}`).join(",");

export class DocumentRejected extends Error {}

export function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot < 0 ? "" : name.slice(dot + 1).toLowerCase();
}

// checkDocument returns the MIME type to record, or throws DocumentRejected
// with a message for the person.
export function checkDocument(name: string, bytes: Uint8Array): string {
  const ext = extensionOf(name);
  if (closed.has(ext)) {
    throw new DocumentRejected(
      `.${ext} is a Microsoft or Apple format and is not accepted. Export it as PDF or as an OpenDocument file (.odt, .ods, .odp) first.`,
    );
  }
  const rule = rules[ext];
  if (!rule) {
    throw new DocumentRejected(`${ext ? `.${ext}` : "Files without an extension"} cannot be attached. Use PDF, OpenDocument, an image (PNG, JPEG, WebP, GIF) or plain text such as TXT, MD, CSV, JSON, YAML or XML.`);
  }
  if (bytes.length === 0) {
    throw new DocumentRejected("The file is empty.");
  }
  if (bytes.length > MAX_DOCUMENT_BYTES) {
    throw new DocumentRejected("Documents can be at most 10 MB.");
  }
  if (!rule.check(bytes)) {
    throw new DocumentRejected(`The contents of "${name}" do not match its .${ext} extension.`);
  }
  return rule.type;
}

// cleanName keeps the last path part and drops control characters.
export function cleanName(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "";
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return (cleaned || "document").slice(0, 200);
}

function startsWith(bytes: Uint8Array, prefix: number[]): boolean {
  return prefix.every((value, index) => bytes[index] === value);
}

function ascii(bytes: Uint8Array, from: number, to: number): string {
  return String.fromCharCode(...bytes.subarray(from, to));
}

function isText(bytes: Uint8Array): boolean {
  if (bytes.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function parses(bytes: Uint8Array): boolean {
  try {
    JSON.parse(new TextDecoder().decode(bytes));
    return true;
  } catch {
    return false;
  }
}

// An OpenDocument file is a ZIP whose first entry is an uncompressed file
// named "mimetype" holding the document type. Office Open XML (.docx) is a
// ZIP too, but never starts this way.
function isOpenDocument(bytes: Uint8Array, kind: string): boolean {
  if (!startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) return false;
  const nameLength = bytes[26] | (bytes[27] << 8);
  const extraLength = bytes[28] | (bytes[29] << 8);
  if (ascii(bytes, 30, 30 + nameLength) !== "mimetype") return false;
  const start = 30 + nameLength + extraLength;
  const expected = `application/vnd.oasis.opendocument.${kind}`;
  return ascii(bytes, start, start + expected.length) === expected;
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Custom fields hold notes such as an account ID or a support PIN. They are
// encrypted like the password, but full card numbers stay out everywhere.
export const MAX_FIELDS = 50;
export const MAX_FIELD_NAME = 160;
export const MAX_FIELD_VALUE = 4000;

export function checkFields(fields: { name: string; value: string }[]): { name: string; value: string }[] {
  const kept = fields
    .map((field) => ({ name: field.name.trim(), value: field.value }))
    .filter((field) => field.name !== "" || field.value.trim() !== "");
  if (kept.length > MAX_FIELDS) {
    throw new DocumentRejected(`An account can have at most ${MAX_FIELDS} extra fields.`);
  }
  for (const field of kept) {
    if (!field.name) throw new DocumentRejected("Give each extra field a name.");
    if (field.name.length > MAX_FIELD_NAME) throw new DocumentRejected(`Field names can be at most ${MAX_FIELD_NAME} characters.`);
    if (field.value.length > MAX_FIELD_VALUE) throw new DocumentRejected(`"${field.name}" is longer than ${MAX_FIELD_VALUE} characters.`);
    if (hasCardNumber(field.name) || hasCardNumber(field.value)) {
      throw new DocumentRejected(`"${field.name}" looks like a full card number. Keep only a name and the last 4 digits.`);
    }
  }
  return kept;
}

// hasCardNumber finds 13 to 19 digits, optionally split by spaces or dashes,
// that pass the Luhn check. The server's plain-text screen (internal/fieldsafe)
// refuses any such digit run; extra fields often hold long account IDs, so
// here only a run that is a valid card number is refused.
export function hasCardNumber(value: string): boolean {
  for (const match of value.matchAll(/\d(?:[ -]?\d){12,18}/g)) {
    const digits = match[0].replace(/\D/g, "");
    if (luhn(digits)) return true;
  }
  return false;
}

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}
