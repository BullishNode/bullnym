// Web NFC (NDEFReader) ambient types — not in TypeScript's default DOM lib.
// Android Chrome only; guarded everywhere by `'NDEFReader' in window`.

interface NDEFRecord {
  recordType: string
  mediaType?: string
  id?: string
  data?: DataView
  encoding?: string
  lang?: string
}

interface NDEFMessage {
  records: NDEFRecord[]
}

interface NDEFReadingEvent extends Event {
  serialNumber: string
  message: NDEFMessage
}

interface NDEFScanOptions {
  signal?: AbortSignal
}

interface NDEFReader extends EventTarget {
  scan(options?: NDEFScanOptions): Promise<void>
  onreading: ((this: NDEFReader, ev: NDEFReadingEvent) => void) | null
  onreadingerror: ((this: NDEFReader, ev: Event) => void) | null
}

declare const NDEFReader: {
  new (): NDEFReader
}
