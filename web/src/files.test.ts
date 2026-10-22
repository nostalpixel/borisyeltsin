import { describe, expect, it } from "vitest";
import { DocumentRejected, MAX_DOCUMENT_BYTES, checkDocument, checkFields, cleanName, hasCardNumber } from "./files";

const bytes = (text: string) => new TextEncoder().encode(text);

// A ZIP local file header whose first entry is "mimetype", as in OpenDocument.
function zipWithMimetype(mimetype: string): Uint8Array {
  const name = bytes("mimetype");
  const header = new Uint8Array(30);
  header.set([0x50, 0x4b, 0x03, 0x04]);
  header[26] = name.length;
  return new Uint8Array([...header, ...name, ...bytes(mimetype), 0x50, 0x4b]);
}

// Office Open XML is a ZIP too, but its first entry is [Content_Types].xml.
function docxLike(): Uint8Array {
  const name = bytes("[Content_Types].xml");
  const header = new Uint8Array(30);
  header.set([0x50, 0x4b, 0x03, 0x04]);
  header[26] = name.length;
  return new Uint8Array([...header, ...name, ...bytes("<Types/>")]);
}

const rejects = (name: string, data: Uint8Array, message: RegExp) => {
  expect(() => checkDocument(name, data)).toThrow(DocumentRejected);
  expect(() => checkDocument(name, data)).toThrow(message);
};

describe("checkDocument", () => {
  it("accepts open formats whose contents match", () => {
    expect(checkDocument("contract.pdf", bytes("%PDF-1.7\n..."))).toBe("application/pdf");
    expect(checkDocument("offer.odt", zipWithMimetype("application/vnd.oasis.opendocument.text"))).toBe("application/vnd.oasis.opendocument.text");
    expect(checkDocument("prices.ods", zipWithMimetype("application/vnd.oasis.opendocument.spreadsheet"))).toBe("application/vnd.oasis.opendocument.spreadsheet");
    expect(checkDocument("scan.PNG", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1]))).toBe("image/png");
    expect(checkDocument("export.csv", bytes("a,b\n1,2\n"))).toBe("text/csv");
    expect(checkDocument("api.json", bytes('{"plan":"team"}'))).toBe("application/json");
    expect(checkDocument("tls.pem", bytes("-----BEGIN CERTIFICATE-----\n"))).toBe("application/x-pem-file");
  });

  it("refuses Microsoft and Apple formats by name", () => {
    for (const name of ["contract.docx", "contract.doc", "budget.xlsx", "deck.pptx", "letter.rtf", "notes.pages", "sheet.numbers", "slides.key", "photo.heic"]) {
      rejects(name, bytes("%PDF-"), /Microsoft or Apple format/);
    }
  });

  it("refuses unknown and active formats", () => {
    rejects("setup.exe", new Uint8Array([0x4d, 0x5a]), /cannot be attached/);
    rejects("page.html", bytes("<script>"), /cannot be attached/);
    rejects("logo.svg", bytes("<svg/>"), /cannot be attached/);
    rejects("archive.zip", docxLike(), /cannot be attached/);
    rejects("README", bytes("hi"), /without an extension/);
  });

  it("checks contents against the extension", () => {
    rejects("contract.odt", docxLike(), /do not match/);
    rejects("contract.odt", zipWithMimetype("application/vnd.oasis.opendocument.spreadsheet"), /do not match/);
    rejects("contract.pdf", bytes("PK\u0003\u0004"), /do not match/);
    rejects("notes.txt", new Uint8Array([0x68, 0x00, 0x69]), /do not match/);
    rejects("notes.txt", new Uint8Array([0xc3, 0x28]), /do not match/);
    rejects("api.json", bytes("{nope"), /do not match/);
  });

  it("refuses empty and oversized files", () => {
    rejects("empty.txt", new Uint8Array(), /empty/);
    rejects("huge.txt", new Uint8Array(MAX_DOCUMENT_BYTES + 1).fill(0x61), /10 MB/);
  });

  it("keeps only the file name", () => {
    expect(cleanName("C:\\Users\\a\\contract.pdf")).toBe("contract.pdf");
    expect(cleanName("../../etc/passwd.txt")).toBe("passwd.txt");
    expect(cleanName("bad\u0000name.pdf")).toBe("badname.pdf");
    expect(cleanName("/")).toBe("document");
  });
});

describe("checkFields", () => {
  it("drops empty rows and trims names", () => {
    expect(checkFields([{ name: " Account ID ", value: "A-42" }, { name: "", value: "  " }])).toEqual([{ name: "Account ID", value: "A-42" }]);
  });

  it("needs a name for a value", () => {
    expect(() => checkFields([{ name: "", value: "orphan" }])).toThrow(/name/);
  });

  it("refuses full card numbers but keeps long IDs", () => {
    expect(hasCardNumber("4111 1111 1111 1111")).toBe(true);
    expect(hasCardNumber("card 5500-0000-0000-0004 exp")).toBe(true);
    expect(hasCardNumber("4111 1111 1111 1112")).toBe(false);
    expect(hasCardNumber("customer 1234567890123")).toBe(false);
    expect(() => checkFields([{ name: "Card", value: "4111111111111111" }])).toThrow(/card number/);
    expect(checkFields([{ name: "Customer", value: "1234567890123" }])).toHaveLength(1);
  });

  it("caps count and length", () => {
    expect(() => checkFields(Array.from({ length: 51 }, (_, i) => ({ name: `f${i}`, value: "x" })))).toThrow(/at most 50/);
    expect(() => checkFields([{ name: "n".repeat(161), value: "x" }])).toThrow(/160/);
    expect(() => checkFields([{ name: "n", value: "v".repeat(4001) }])).toThrow(/4000/);
  });
});
