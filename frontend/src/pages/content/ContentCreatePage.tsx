import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertCircle,
  CheckCircle2,
  File,
  Loader2,
  Upload,
  Lock,
  Globe,
  Activity,
  Cpu,
  Layers,
  Video,
  Image as ImageIcon,
  Music,
  Terminal,
  Trash2,
  Settings
} from 'lucide-react';
import axios from 'axios';
import apiClient from '../../lib/axios';
import { hashFileInChunks } from '../../lib/crypto';

interface ExtractedMetadata {
  width?: number;
  height?: number;
  duration?: number;
  wordCount?: number;
  lineCount?: number;
  characterCount?: number;
  textPreview?: string;
  formattedSize: string;
}

interface ChunkStatus {
  index: number;
  hash?: string;
  status: 'pending' | 'hashing' | 'completed';
}

function ContentCreatePage() {
  const navigate = useNavigate();

  // File & State Management
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [fileCategory, setFileCategory] = useState<'image' | 'video' | 'audio' | 'text' | 'document' | null>(null);
  const [extractedMetadata, setExtractedMetadata] = useState<ExtractedMetadata | null>(null);

  // Hashing Operations State
  const [isHashing, setIsHashing] = useState(false);
  const [hashingProgress, setHashingProgress] = useState(0);
  const [chunkStatus, setChunkStatus] = useState<ChunkStatus[]>([]);
  const [hashConsoleLogs, setHashConsoleLogs] = useState<string[]>([]);
  const consoleRef = useRef<HTMLDivElement>(null);

  // Network Upload State
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadSpeed, setUploadSpeed] = useState<number>(0);
  const [uploadEta, setUploadEta] = useState<number | null>(null);

  const [cryptoResult, setCryptoResult] = useState<{
    originalHash: string;
    chunkHashes: string[];
    merkleRoot: string;
  } | null>(null);

  // Metadata Form State
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [tagsInput, setTagsInput] = useState('');
  const [isPublic, setIsPublic] = useState(false);

  // Submit UI State
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  // Auto-scroll console
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [hashConsoleLogs]);

  // Clean up Object URL previews on unmount
  useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  const extractFileMetadata = async (selectedFile: File, category: 'image' | 'video' | 'audio' | 'text' | 'document') => {
    const formattedSize = (selectedFile.size / (1024 * 1024)).toFixed(2) + ' MB';
    const metadata: ExtractedMetadata = { formattedSize };

    try {
      if (category === 'image') {
        const dims = await new Promise<{ width: number; height: number }>((resolve, reject) => {
          const img = new Image();
          img.src = URL.createObjectURL(selectedFile);
          img.onload = () => {
            resolve({ width: img.width, height: img.height });
            URL.revokeObjectURL(img.src);
          };
          img.onerror = () => {
            reject(new Error('Failed to load image metadata'));
            URL.revokeObjectURL(img.src);
          };
        });
        metadata.width = dims.width;
        metadata.height = dims.height;
      } else if (category === 'video' || category === 'audio') {
        const media = await new Promise<{ duration: number; width?: number; height?: number }>((resolve) => {
          const el = document.createElement(category === 'video' ? 'video' : 'audio');
          el.src = URL.createObjectURL(selectedFile);
          el.preload = 'metadata';
          el.onloadedmetadata = () => {
            const res: { duration: number; width?: number; height?: number } = { duration: el.duration };
            if (category === 'video') {
              const videoEl = el as HTMLVideoElement;
              res.width = videoEl.videoWidth;
              res.height = videoEl.videoHeight;
            }
            resolve(res);
            URL.revokeObjectURL(el.src);
          };
          el.onerror = () => {
            resolve({ duration: 0 });
            URL.revokeObjectURL(el.src);
          };
        });
        metadata.duration = media.duration;
        if (media.width && media.height) {
          metadata.width = media.width;
          metadata.height = media.height;
        }
      } else if (category === 'text') {
        const stats = await new Promise<{ wordCount: number; lineCount: number; characterCount: number; preview: string }>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = (e) => {
            const text = e.target?.result as string || '';
            const lines = text.split('\n');
            const words = text.trim().split(/\s+/).filter(w => w.length > 0);
            resolve({
              wordCount: words.length,
              lineCount: lines.length,
              characterCount: text.length,
              preview: text.substring(0, 500)
            });
          };
          reader.onerror = () => reject(new Error('Failed to read text stream'));
          reader.readAsText(selectedFile.slice(0, 1024 * 50));
        });
        metadata.wordCount = stats.wordCount;
        metadata.lineCount = stats.lineCount;
        metadata.characterCount = stats.characterCount;
        metadata.textPreview = stats.preview;
      }
    } catch (err) {
      console.error('Error extracting file metrics:', err);
    }

    setExtractedMetadata(metadata);
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;
    await processFile(selectedFile);
  };

  const processFile = async (selectedFile: File) => {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }

    setFile(selectedFile);
    setCryptoResult(null);
    setErrorMessage('');
    setIsHashing(true);
    setHashingProgress(0);
    setUploadProgress(0);
    setUploadSpeed(0);
    setUploadEta(null);

    const mimeType = selectedFile.type || 'application/octet-stream';
    let category: 'image' | 'video' | 'audio' | 'text' | 'document' = 'document';
    if (mimeType.startsWith('image/')) category = 'image';
    else if (mimeType.startsWith('video/')) category = 'video';
    else if (mimeType.startsWith('audio/')) category = 'audio';
    else if (mimeType.startsWith('text/')) category = 'text';
    else if (selectedFile.name.endsWith('.txt') || selectedFile.name.endsWith('.md') || selectedFile.name.endsWith('.json')) category = 'text';

    setFileCategory(category);

    if (category === 'image' || category === 'video' || category === 'audio') {
      setPreviewUrl(URL.createObjectURL(selectedFile));
    } else {
      setPreviewUrl(null);
    }

    if (!title) {
      const cleanTitle = selectedFile.name.replace(/\.[^/.]+$/, "");
      setTitle(cleanTitle);
    }

    // Extract metadata
    extractFileMetadata(selectedFile, category);

    // Initialize Hashing Grid & Terminal Logger
    const chunkSize = 1024 * 1024; // 1MB chunks
    const totalChunks = Math.ceil(selectedFile.size / chunkSize);
    const initialStatus = Array.from({ length: totalChunks }, (_, idx) => ({
      index: idx,
      status: 'pending' as const
    }));
    setChunkStatus(initialStatus);

    const formatLogTime = () => {
      const now = new Date();
      return now.toLocaleTimeString();
    };

    const logs = [
      `[${formatLogTime()}] INITIALIZING INTEGRITY VERIFICATION FOR "${selectedFile.name.toUpperCase()}"`,
      `[${formatLogTime()}] FILE SIZE: ${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB (${selectedFile.size} BYTES)`,
      `[${formatLogTime()}] SEGMENTATION: ${totalChunks} CHUNKS OF SIZE ${(chunkSize / (1024 * 1024)).toFixed(2)} MB`,
      `[${formatLogTime()}] STARTING SHA-256 HASH CALCULATION...`
    ];
    setHashConsoleLogs(logs);

    try {
      setChunkStatus(prev => prev.map((c, idx) => idx === 0 ? { ...c, status: 'hashing' } : c));

      const result = await hashFileInChunks(
        selectedFile,
        chunkSize,
        (progress) => {
          setHashingProgress(progress);
        },
        (chunkIndex, hash) => {
          setChunkStatus(prev => prev.map((c, idx) => {
            if (idx === chunkIndex) return { ...c, status: 'completed', hash };
            if (idx === chunkIndex + 1) return { ...c, status: 'hashing' };
            return c;
          }));

          setHashConsoleLogs(prev => [
            ...prev,
            `[${formatLogTime()}] CHUNK #${chunkIndex + 1}/${totalChunks} PROCESSED: ${hash.substring(0, 16)}...`
          ]);
        }
      );

      setHashConsoleLogs(prev => [
        ...prev,
        `[${formatLogTime()}] ASSEMBLING CRYPTOGRAPHIC DATA STRUCTURE...`,
        `[${formatLogTime()}] MERKLE ROOT GENERATED: ${result.merkleRoot}`,
        `[${formatLogTime()}] FILE HASH: ${result.originalHash}`,
        `[${formatLogTime()}] STATUS: VERIFICATION COMPLETED. INTEGRITY GUARANTEED.`
      ]);

      setCryptoResult(result);
    } catch (err) {
      setErrorMessage('Failed to calculate file hash: ' + (err as Error).message);
      setFile(null);
      setHashConsoleLogs(prev => [
        ...prev,
        `[${formatLogTime()}] ERROR: FILE HASHING FAILED: ${(err as Error).message.toUpperCase()}`
      ]);
    } finally {
      setIsHashing(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files?.[0];
    if (droppedFile) {
      await processFile(droppedFile);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || !cryptoResult) {
      setErrorMessage('Please select and verify a file first.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage('');
    setIsUploading(true);
    setUploadProgress(0);

    const uploadStartTime = Date.now();

    const tags = tagsInput
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0)
      .slice(0, 10);

    const mimeType = file.type || 'application/octet-stream';
    let contentType = 'document';
    if (mimeType.startsWith('image/')) contentType = 'image';
    else if (mimeType.startsWith('video/')) contentType = 'video';
    else if (mimeType.startsWith('audio/')) contentType = 'audio';
    else if (mimeType.startsWith('text/')) contentType = 'text';

    try {
      // 1. Get upload config parameters
      const paramsResponse = await apiClient.post<{
        provider: 's3' | 'local';
        method: 'PUT' | 'POST';
        uploadUrl: string;
        downloadUrl: string;
        key: string;
        headers?: Record<string, string>;
      }>('/content/upload-params', {
        fileName: file.name,
        fileType: mimeType
      });

      const { provider, uploadUrl, downloadUrl, key, headers } = paramsResponse.data;

      const trackProgress = (progressEvent: any) => {
        if (progressEvent.total) {
          const pct = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setUploadProgress(pct);

          const elapsedSeconds = (Date.now() - uploadStartTime) / 1000;
          if (elapsedSeconds > 0) {
            const bytesPerSecond = progressEvent.loaded / elapsedSeconds;
            const speedMBs = bytesPerSecond / (1024 * 1024);
            setUploadSpeed(speedMBs);

            const remainingBytes = progressEvent.total - progressEvent.loaded;
            const etaSeconds = remainingBytes / bytesPerSecond;
            setUploadEta(Math.round(etaSeconds));
          }
        }
      };

      // 2. Upload file binary
      if (provider === 's3') {
        const cleanAxios = axios.create();
        await cleanAxios.put(uploadUrl, file, {
          headers: {
            ...headers,
            'Content-Type': mimeType
          },
          onUploadProgress: trackProgress
        });
      } else {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('key', key);

        await apiClient.post(uploadUrl, formData, {
          headers: {
            'Content-Type': 'multipart/form-data'
          },
          onUploadProgress: trackProgress
        });
      }

      setIsUploading(false);

      // 3. Register Content in backend Mongoose DB
      await apiClient.post('/content', {
        title,
        description,
        contentType,
        originalHash: cryptoResult.originalHash,
        merkleRoot: cryptoResult.merkleRoot,
        chunkHashes: cryptoResult.chunkHashes,
        fileSize: file.size,
        mimeType,
        tags,
        isPublic,
        metadata: {
          storageUrl: downloadUrl,
          storageProvider: provider,
          storageKey: key
        }
      });

      setSuccessMessage('Evidence successfully uploaded and verified!');
      setTimeout(() => {
        navigate('/content');
      }, 1500);
    } catch (error) {
      const message = (error as { response?: { data?: { error?: string } } })
        .response?.data?.error || 'Failed to save evidence details to registry';
      setErrorMessage(message);
    } finally {
      setIsSubmitting(false);
      setIsUploading(false);
    }
  };

  const clearFileSelection = () => {
    setFile(null);
    setPreviewUrl(null);
    setFileCategory(null);
    setExtractedMetadata(null);
    setCryptoResult(null);
    setChunkStatus([]);
    setHashConsoleLogs([]);
    setHashingProgress(0);
    setUploadProgress(0);
    setUploadSpeed(0);
    setUploadEta(null);
  };

  return (
    <section className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
          <Activity className="h-8 w-8 text-cyan-400" />
          Upload Evidence
        </h1>
        <p className="text-gray-400">Generate a cryptographic signature and upload evidence files for validation.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column */}
        <div className="space-y-6 lg:col-span-2">
          {/* File Handler Card */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm shadow-xl">
            {!file ? (
              <div
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                className="relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-gray-800 bg-gray-950/20 hover:border-cyan-500/40 hover:bg-cyan-950/5 p-12 text-center transition-all cursor-pointer group"
              >
                <input
                  type="file"
                  id="file-upload"
                  onChange={handleFileChange}
                  disabled={isHashing || isSubmitting || isUploading}
                  className="absolute inset-0 cursor-pointer opacity-0"
                />
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-gray-900 border border-gray-800 group-hover:border-cyan-500/50 group-hover:text-cyan-400 transition-all shadow-inner">
                  <Upload className="h-8 w-8 text-gray-400 group-hover:text-cyan-400 group-hover:scale-110 transition-transform" />
                </div>
                <div className="mt-6 space-y-2">
                  <p className="font-semibold text-white text-base">Drag & drop your file here, or click to browse</p>
                  <p className="text-xs text-gray-500 max-w-sm mx-auto">
                    Supported media: high-resolution videos, images, audio files, text or PDF documents.
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-6">
                <div className="flex items-center justify-between border-b border-gray-800 pb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded bg-cyan-950/40 border border-cyan-800/30 text-cyan-400">
                      {fileCategory === 'image' && <ImageIcon className="h-5 w-5" />}
                      {fileCategory === 'video' && <Video className="h-5 w-5" />}
                      {fileCategory === 'audio' && <Music className="h-5 w-5" />}
                      {fileCategory === 'text' && <File className="h-5 w-5" />}
                      {fileCategory === 'document' && <File className="h-5 w-5" />}
                    </div>
                    <div>
                      <p className="font-semibold text-white text-sm max-w-[280px] sm:max-w-md truncate">{file.name}</p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        {extractedMetadata?.formattedSize} • {file.type || 'Unknown MIME'}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={clearFileSelection}
                    disabled={isHashing || isUploading || isSubmitting}
                    className="flex items-center gap-1 text-gray-500 hover:text-red-400 text-xs px-2.5 py-1.5 rounded-lg hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-all disabled:opacity-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    <span>Clear</span>
                  </button>
                </div>

                {/* Previews Frame */}
                <div className="bg-gray-950/50 rounded-xl overflow-hidden border border-gray-900">
                  {fileCategory === 'image' && previewUrl && (
                    <div className="relative group aspect-video flex items-center justify-center p-2">
                      <img src={previewUrl} alt="Preview" className="max-h-[300px] max-w-full object-contain rounded-lg shadow-2xl" />
                      <div className="absolute inset-0 bg-gradient-to-t from-gray-950 via-transparent to-transparent opacity-40" />
                    </div>
                  )}

                  {fileCategory === 'video' && previewUrl && (
                    <div className="relative aspect-video flex items-center justify-center p-2">
                      <video src={previewUrl} controls className="max-h-[300px] w-full object-contain rounded-lg shadow-2xl" />
                    </div>
                  )}

                  {fileCategory === 'audio' && previewUrl && (
                    <div className="p-6 space-y-4">
                      <audio src={previewUrl} controls className="w-full" />
                      <div className="flex items-end gap-0.5 justify-center h-12 py-1 bg-gray-950/60 rounded-xl border border-gray-900">
                        {[...Array(30)].map((_, i) => (
                          <motion.div
                            key={i}
                            className="w-1 bg-cyan-400/80 rounded-full"
                            animate={{
                              height: [6, Math.random() * 32 + 6, 6]
                            }}
                            transition={{
                              duration: 0.5 + Math.random() * 0.5,
                              repeat: Infinity,
                              ease: "easeInOut"
                            }}
                          />
                        ))}
                      </div>
                    </div>
                  )}

                  {fileCategory === 'text' && extractedMetadata?.textPreview && (
                    <div className="p-4 space-y-2">
                      <div className="bg-gray-950 border border-gray-900 rounded-lg p-4 font-mono text-xs text-emerald-400 max-h-48 overflow-y-auto whitespace-pre-wrap select-text leading-relaxed">
                        {extractedMetadata.textPreview}
                      </div>
                    </div>
                  )}

                  {fileCategory === 'document' && (
                    <div className="p-8 flex flex-col items-center justify-center text-center space-y-3">
                      <div className="p-4 rounded-full bg-gray-900 border border-gray-800 text-gray-400">
                        <File className="h-12 w-12" />
                      </div>
                      <div>
                        <p className="font-semibold text-white text-sm">No Live Preview Available</p>
                        <p className="text-xs text-gray-500 mt-1 uppercase tracking-wider">SECURED DOCUMENT CONTAINER</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Progress Indicators */}
                <AnimatePresence>
                  {isHashing && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="space-y-2 bg-amber-950/10 border border-amber-500/20 rounded-xl p-4 font-mono text-xs"
                    >
                      <div className="flex justify-between text-amber-400 font-semibold">
                        <span className="flex items-center gap-1.5">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          CALCULATING FILE INTEGRITY
                        </span>
                        <span>{hashingProgress}%</span>
                      </div>
                      <div className="h-1.5 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-800">
                        <motion.div
                          className="h-full bg-amber-500"
                          initial={{ width: 0 }}
                          animate={{ width: `${hashingProgress}%` }}
                          transition={{ duration: 0.1 }}
                        />
                      </div>
                    </motion.div>
                  )}

                  {isUploading && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="space-y-2 bg-cyan-950/10 border border-cyan-500/20 rounded-xl p-4 font-mono text-xs"
                    >
                      <div className="flex justify-between text-cyan-400 font-semibold">
                        <span className="flex items-center gap-1.5">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          UPLOADING FILE...
                        </span>
                        <span>{uploadProgress}%</span>
                      </div>
                      <div className="h-1.5 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-800">
                        <motion.div
                          className="h-full bg-cyan-500"
                          initial={{ width: 0 }}
                          animate={{ width: `${uploadProgress}%` }}
                          transition={{ duration: 0.1 }}
                        />
                      </div>
                      <div className="flex justify-between text-gray-500 mt-1">
                        <span>SPEED: {uploadSpeed.toFixed(2)} MB/s</span>
                        <span>ETA: {uploadEta !== null ? `${uploadEta}s` : 'CALCULATING...'}</span>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}
          </div>

          {/* Form Specifications */}
          {file && (
            <motion.form
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              onSubmit={handleSubmit}
              className="space-y-6 rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm shadow-xl"
            >
              <h2 className="text-lg font-semibold text-white flex items-center gap-2 border-b border-gray-800 pb-3">
                <Settings className="h-5 w-5 text-cyan-400" />
                Evidence Details
              </h2>

              <div className="space-y-4">
                <div>
                  <label htmlFor="title" className="mb-1.5 block text-sm font-medium text-gray-300">Title</label>
                  <input
                    id="title"
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                    maxLength={200}
                    disabled={isHashing || isUploading || isSubmitting}
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3.5 py-2.5 text-sm text-white outline-none ring-cyan-500/20 focus:ring focus:border-cyan-500 placeholder-gray-600 transition"
                  />
                </div>

                <div>
                  <label htmlFor="description" className="mb-1.5 block text-sm font-medium text-gray-300">Description</label>
                  <textarea
                    id="description"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    maxLength={1000}
                    rows={4}
                    disabled={isHashing || isUploading || isSubmitting}
                    placeholder="Provide details about the evidence source, custody context, or case associations."
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3.5 py-2.5 text-sm text-white outline-none ring-cyan-500/20 focus:ring focus:border-cyan-500 placeholder-gray-600 resize-none transition"
                  />
                </div>

                <div>
                  <label htmlFor="tags" className="mb-1.5 block text-sm font-medium text-gray-300">Tags (comma-separated)</label>
                  <input
                    id="tags"
                    type="text"
                    placeholder="e.g. metadata-audit, document-integrity, transcript"
                    value={tagsInput}
                    onChange={(e) => setTagsInput(e.target.value)}
                    disabled={isHashing || isUploading || isSubmitting}
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3.5 py-2.5 text-sm text-white outline-none ring-cyan-500/20 focus:ring focus:border-cyan-500 placeholder-gray-600 transition"
                  />
                </div>

                <div className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-950/30 p-4">
                  <div className="flex flex-col gap-1 pr-4">
                    <span className="text-sm font-medium text-white flex items-center gap-2">
                      {isPublic ? <Globe className="h-4.5 w-4.5 text-cyan-400" /> : <Lock className="h-4.5 w-4.5 text-gray-500" />}
                      Public Verification Availability
                    </span>
                    <span className="text-xs text-gray-400">If enabled, anyone can search and verify this content hash in the public registry.</span>
                  </div>
                  <button
                    type="button"
                    disabled={isHashing || isUploading || isSubmitting}
                    onClick={() => setIsPublic(prev => !prev)}
                    className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out outline-none disabled:opacity-50 ${
                      isPublic ? 'bg-cyan-500' : 'bg-gray-800'
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        isPublic ? 'translate-x-5' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>
              </div>

              {errorMessage && (
                <div className="flex items-center gap-3 rounded-lg bg-red-500/10 border border-red-500/20 p-4 text-sm text-red-400">
                  <AlertCircle className="h-5 w-5 flex-shrink-0" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {successMessage && (
                <div className="flex items-center gap-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-4 text-sm text-emerald-400">
                  <CheckCircle2 className="h-5 w-5 flex-shrink-0" />
                  <span>{successMessage}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={isHashing || isUploading || isSubmitting || !cryptoResult}
                className="flex w-full items-center justify-center gap-2.5 rounded-lg bg-cyan-400 py-3 text-sm font-semibold text-gray-950 shadow-lg shadow-cyan-400/15 hover:shadow-cyan-400/25 hover:bg-cyan-300 transition duration-150 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isUploading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Uploading Evidence ({uploadProgress}%)...</span>
                  </>
                ) : isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Saving evidence details to registry...</span>
                  </>
                ) : isHashing ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Calculating file integrity...</span>
                  </>
                ) : (
                  <span>Upload & Verify Evidence</span>
                )}
              </button>
            </motion.form>
          )}
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Cryptographic Console */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm shadow-xl space-y-4 flex flex-col h-[380px]">
            <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-gray-800 pb-2">
              <Terminal className="h-4.5 w-4.5 text-amber-400" />
              Integrity Verification Console
            </h2>

            <div
              ref={consoleRef}
              className="flex-1 rounded-xl bg-black/80 border border-gray-950 p-4 font-mono text-[10px] text-amber-500/80 overflow-y-auto space-y-1.5 scrollbar-thin select-all"
            >
              {hashConsoleLogs.length > 0 ? (
                hashConsoleLogs.map((log, idx) => (
                  <div key={idx} className="leading-relaxed break-all">
                    {log}
                  </div>
                ))
              ) : (
                <div className="text-gray-600 flex flex-col justify-center items-center h-full text-center space-y-2">
                  <Terminal className="h-8 w-8 text-gray-800" />
                  <span>AWAITING FILE UPLOAD...</span>
                </div>
              )}
            </div>

            {/* Chunk status grid */}
            {chunkStatus.length > 0 && (
              <div className="space-y-2">
                <span className="text-[10px] font-mono text-gray-500 font-bold uppercase">FILE CHUNKS PROCESS:</span>
                <div className="flex flex-wrap gap-1 bg-black/45 border border-gray-950 p-3 rounded-lg max-h-24 overflow-y-auto">
                  {chunkStatus.map((chunk, idx) => (
                    <div
                      key={idx}
                      title={`Chunk #${idx + 1}: ${chunk.hash || 'WAITING'}`}
                      className={`h-3 w-3 rounded-sm transition-all duration-300 ${
                        chunk.status === 'completed'
                          ? 'bg-emerald-500 shadow-[0_0_6px_#10b981] scale-100'
                          : chunk.status === 'hashing'
                          ? 'bg-amber-400 shadow-[0_0_6px_#f59e0b] scale-110 animate-pulse'
                          : 'bg-gray-800 border border-gray-700/50 scale-95'
                      }`}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* File Details Sheet */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm shadow-xl space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-gray-800 pb-2">
              <Cpu className="h-4.5 w-4.5 text-cyan-400" />
              File Details
            </h2>

            {file ? (
              <div className="space-y-3 text-xs font-mono">
                <div className="flex justify-between border-b border-gray-950 pb-2">
                  <span className="text-gray-500">FILE TYPE</span>
                  <span className="text-cyan-400 font-semibold uppercase">{fileCategory}</span>
                </div>
                <div className="flex justify-between border-b border-gray-950 pb-2">
                  <span className="text-gray-500">FILE SIZE</span>
                  <span className="text-white">{file.size.toLocaleString()} BYTES</span>
                </div>
                {extractedMetadata?.width && extractedMetadata?.height && (
                  <div className="flex justify-between border-b border-gray-950 pb-2">
                    <span className="text-gray-500">DIMENSIONS</span>
                    <span className="text-white">
                      {extractedMetadata.width} × {extractedMetadata.height} ({ (extractedMetadata.width / extractedMetadata.height).toFixed(2) }:1)
                    </span>
                  </div>
                )}
                {extractedMetadata?.duration !== undefined && extractedMetadata.duration > 0 && (
                  <div className="flex justify-between border-b border-gray-950 pb-2">
                    <span className="text-gray-500">DURATION</span>
                    <span className="text-white">
                      {Math.floor(extractedMetadata.duration / 60)}:{('0' + Math.floor(extractedMetadata.duration % 60)).slice(-2)} ({(extractedMetadata.duration).toFixed(2)}s)
                    </span>
                  </div>
                )}
                {extractedMetadata?.wordCount !== undefined && (
                  <>
                    <div className="flex justify-between border-b border-gray-950 pb-2">
                      <span className="text-gray-500">LINE COUNT</span>
                      <span className="text-white">{extractedMetadata.lineCount}</span>
                    </div>
                    <div className="flex justify-between border-b border-gray-950 pb-2">
                      <span className="text-gray-500">WORD COUNT</span>
                      <span className="text-white">{extractedMetadata.wordCount}</span>
                    </div>
                    <div className="flex justify-between border-b border-gray-950 pb-2">
                      <span className="text-gray-500">CHAR COUNT</span>
                      <span className="text-white">{extractedMetadata.characterCount}</span>
                    </div>
                  </>
                )}
                <div className="flex justify-between border-b border-gray-950 pb-2">
                  <span className="text-gray-500">LAST MODIFIED</span>
                  <span className="text-white truncate max-w-[150px]">{new Date(file.lastModified).toISOString()}</span>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-500 py-8 text-xs font-mono">
                AWAITING FILE METADATA...
              </div>
            )}
          </div>

          {/* Integrity Details */}
          <div className="rounded-2xl border border-gray-800 bg-gray-900/40 p-6 backdrop-blur-sm shadow-xl space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-gray-800 pb-2">
              <Layers className="h-4.5 w-4.5 text-emerald-400" />
              Integrity Details
            </h2>

            {cryptoResult ? (
              <div className="space-y-4 text-xs font-mono">
                <div className="space-y-1">
                  <span className="text-gray-500 block">SHA-256 HASH</span>
                  <div className="rounded-lg bg-gray-950 border border-gray-900 p-2.5 break-all text-[10px] text-gray-300 select-all select-none">
                    {cryptoResult.originalHash}
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-emerald-500/70 block">MERKLE ROOT</span>
                  <div className="rounded-lg bg-gray-950 border border-emerald-950 p-2.5 break-all text-[10px] text-emerald-400 select-all select-none">
                    {cryptoResult.merkleRoot}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-center text-[10px]">
                  <div className="rounded-lg bg-gray-950 border border-gray-900 p-2">
                    <span className="text-gray-500 block">TOTAL CHUNKS</span>
                    <span className="text-sm font-bold text-white mt-1 block">{cryptoResult.chunkHashes.length}</span>
                  </div>
                  <div className="rounded-lg bg-gray-950 border border-gray-900 p-2">
                    <span className="text-gray-500 block">CHUNK SIZE</span>
                    <span className="text-sm font-bold text-white mt-1 block">1.00 MB</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-500 py-8 text-xs font-mono">
                AWAITING INTEGRITY PROCESS...
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default ContentCreatePage;
