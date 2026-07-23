"use client";

import { useEffect, useRef, useState, type DragEvent } from "react";
import { UploadCloud, Loader2, ImagePlus, X } from "lucide-react";
import type { AnalysisResult, ContentType } from "@/core/types";
import { DEMO_INPUTS } from "@/core/demo-inputs";
import ThreatReport from "./components/ThreatReport";
import Overview from "./components/Overview";

type TypeChoice = "auto" | Exclude<ContentType, "image">;
const TABS: { id: TypeChoice; label: string }[] = [
  { id: "auto", label: "Auto" },
  { id: "email", label: "Email" },
  { id: "url", label: "URL" },
  { id: "text", label: "Text" },
];

const MAX_IMAGES = 3;

interface Shot {
  id: string;
  url: string; // object URL for the thumbnail
  blob: Blob; // downscaled JPEG for upload
}

/**
 * A stable id. crypto.randomUUID exists only in a secure context — it is absent
 * when the app is opened over a plain-HTTP LAN address (e.g. http://192.168.x.x
 * from a phone), where relying on it throws and silently kills image adds. Fall
 * back to a timestamp+random id so uploads work everywhere.
 */
function uid(): string {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  } catch {
    // fall through
  }
  return `id-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/**
 * Downscale to a 1400px long edge at JPEG 0.85 before upload. Phone screenshots
 * arrive at 3x and we would otherwise pay image tokens for pixels the OCR never
 * uses. We never go below ~1200px: homoglyph fidelity (digit-one vs letter-L)
 * degrades and that is exactly what the typosquat detector depends on.
 */
async function downscale(file: File): Promise<Shot> {
  try {
    const bitmap = await createImageBitmap(file);
    const MAX = 1400;
    const long = Math.max(bitmap.width, bitmap.height);
    const scale = long > MAX ? MAX / long : 1;
    const w = Math.round(bitmap.width * scale);
    const h = Math.round(bitmap.height * scale);
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    canvas.getContext("2d")!.drawImage(bitmap, 0, 0, w, h);
    const blob = await new Promise<Blob>((res, rej) => canvas.toBlob((b) => (b ? res(b) : rej()), "image/jpeg", 0.85));
    return { id: uid(), url: URL.createObjectURL(blob), blob };
  } catch {
    // e.g. HEIC that the browser cannot decode: send the original, let the server transcribe it.
    return { id: uid(), url: URL.createObjectURL(file), blob: file };
  }
}

export default function Home() {
  const [content, setContent] = useState("");
  const [typeChoice, setTypeChoice] = useState<TypeChoice>("auto");
  const [images, setImages] = useState<Shot[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [hot, setHot] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  async function addFiles(files: FileList | File[]) {
    const list = Array.from(files);
    const imgs = list.filter((f) => f.type.startsWith("image/"));
    const textFile = list.find((f) => !f.type.startsWith("image/"));
    if (textFile) {
      const t = await textFile.text();
      setContent(t);
      setResult(null);
      setError(null);
    }
    if (imgs.length) {
      const room = MAX_IMAGES - images.length;
      const shots = await Promise.all(imgs.slice(0, room).map(downscale));
      setImages((prev) => [...prev, ...shots].slice(0, MAX_IMAGES));
      setResult(null);
      setError(null);
    }
  }

  function removeImage(id: string) {
    setImages((prev) => prev.filter((s) => s.id !== id));
  }

  async function submit() {
    if (loading) return;
    const text = content.trim();
    if (images.length === 0 && !text) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      let res: Response;
      if (images.length > 0) {
        const fd = new FormData();
        images.forEach((s, i) => fd.append("images", s.blob, `screenshot-${i}.jpg`));
        res = await fetch("/api/analyze", { method: "POST", body: fd });
      } else {
        res = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: text, contentType: typeChoice === "auto" ? undefined : typeChoice }),
        });
      }
      const data = await res.json();
      if (!res.ok) setError(data.error ?? "Analysis failed.");
      else setResult(data as AnalysisResult);
    } catch {
      setError("Could not reach the analysis service.");
    } finally {
      setLoading(false);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setHot(false);
    if (e.dataTransfer.files?.length) addFiles(e.dataTransfer.files);
  }

  // Paste a screenshot from the clipboard (Cmd/Ctrl+V) anywhere on the page — not
  // only when the drop zone has focus. Text pastes fall through to the textarea
  // untouched; only image files are intercepted.
  useEffect(() => {
    function onPaste(e: ClipboardEvent) {
      const items = e.clipboardData?.items;
      if (!items) return;
      const files = Array.from(items)
        .filter((it) => it.kind === "file" && it.type.startsWith("image/"))
        .map((it) => it.getAsFile())
        .filter((f): f is File => f !== null);
      if (files.length) {
        e.preventDefault();
        addFiles(files);
      }
    }
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [images]);

  const canSubmit = !loading && (images.length > 0 || content.trim().length > 0);

  return (
    <div className="workspace">
      <div className="left-col">
        <div className="card">
          <div className="console-head">
            <span className="tracking-label">Intake</span>
            <span className="armed">▲ ARMED</span>
          </div>
          <div className="seg">
            {TABS.map((t) => (
              <button key={t.id} className={typeChoice === t.id ? "active" : ""} onClick={() => setTypeChoice(t.id)}>
                {t.label}
              </button>
            ))}
          </div>

          <div
            className={`dropzone ${hot ? "hot" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setHot(true);
            }}
            onDragEnter={(e) => {
              e.preventDefault();
              setHot(true);
            }}
            onDragLeave={() => setHot(false)}
            onDrop={onDrop}
          >
            <span className="dz-corner tl" aria-hidden="true" />
            <span className="dz-corner tr" aria-hidden="true" />
            <span className="dz-corner bl" aria-hidden="true" />
            <span className="dz-corner br" aria-hidden="true" />
            {!content && images.length === 0 && <div className="dz-sweep" aria-hidden="true" />}
            {loading && <div className="scanline" />}
            <div className={`dz-hint ${content || images.length ? "hidden" : ""}`}>
              <div className="dz-chip">
                <UploadCloud size={26} strokeWidth={1.5} />
              </div>
              <div>
                <div className="dz-title">Drop a screenshot or file</div>
                <div className="dz-sub">image, .eml or .txt &nbsp;·&nbsp; or paste &nbsp;·&nbsp; or click to type</div>
              </div>
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              spellCheck={false}
              aria-label="Content to analyse"
              style={{ display: images.length ? "none" : "block" }}
            />
            {images.length > 0 && (
              <div className="thumbs">
                {images.map((s) => (
                  <div className="thumb" key={s.id}>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={s.url} alt="screenshot preview" />
                    <button className="thumb-x" onClick={() => removeImage(s.id)} aria-label="Remove image">
                      <X size={13} strokeWidth={2} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="dz-actions">
            <button
              className="ghost-btn"
              onClick={() => fileInput.current?.click()}
              disabled={images.length >= MAX_IMAGES}
            >
              <ImagePlus size={15} strokeWidth={1.5} />
              Add screenshot
            </button>
            <input
              ref={fileInput}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/heic,image/heif"
              multiple
              hidden
              onChange={(e) => {
                if (e.target.files) addFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </div>

          <button className="analyse-btn" onClick={submit} disabled={!canSubmit}>
            {loading ? <Loader2 size={16} strokeWidth={1.5} className="spin" /> : <span aria-hidden="true">▶</span>}
            {loading
              ? "ANALYSING"
              : images.length
                ? `ANALYSE ${images.length} SHOT${images.length > 1 ? "S" : ""}`
                : "ANALYSE"}
          </button>
        </div>

        <div className="card">
          <div className="tracking-label" style={{ marginBottom: 12 }}>
            Examples
          </div>
          <div className="chips">
            {DEMO_INPUTS.map((d) => (
              <button
                key={d.id}
                onClick={() => {
                  setContent(d.text);
                  setImages([]);
                  setResult(null);
                  setError(null);
                }}
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div>
        {error && <div className="error-banner">{error}</div>}
        {result ? (
          <ThreatReport
            key={result.id}
            result={result}
            onReset={() => {
              setResult(null);
              setContent("");
              setImages([]);
              setError(null);
            }}
          />
        ) : (
          !error && <Overview />
        )}
      </div>
    </div>
  );
}
