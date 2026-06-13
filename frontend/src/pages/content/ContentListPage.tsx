import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { 
  FileText, Film, Image, Music, File, 
  ChevronLeft, ChevronRight, Filter, 
  Calendar, Layers, CheckCircle2, AlertTriangle, XCircle, Clock
} from 'lucide-react';
import apiClient from '../../lib/axios';
import type { Content, PaginatedResponse } from '../../types';

function getStatusBadge(status: string) {
  switch (status) {
    case 'verified':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-0.5 text-xs font-semibold text-emerald-400">
          <CheckCircle2 className="h-3 w-3" />
          <span>Verified</span>
        </span>
      );
    case 'flagged':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 border border-amber-500/20 px-2.5 py-0.5 text-xs font-semibold text-amber-400">
          <AlertTriangle className="h-3 w-3" />
          <span>Flagged</span>
        </span>
      );
    case 'rejected':
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 border border-red-500/20 px-2.5 py-0.5 text-xs font-semibold text-red-400">
          <XCircle className="h-3 w-3" />
          <span>Rejected</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-gray-500/10 border border-gray-500/20 px-2.5 py-0.5 text-xs font-semibold text-gray-400">
          <Clock className="h-3 w-3" />
          <span>Pending</span>
        </span>
      );
  }
}

function getFileTypeIcon(type: string) {
  switch (type) {
    case 'video': return <Film className="h-4 w-4" />;
    case 'image': return <Image className="h-4 w-4" />;
    case 'audio': return <Music className="h-4 w-4" />;
    case 'text': return <FileText className="h-4 w-4" />;
    default: return <File className="h-4 w-4" />;
  }
}

function ContentListPage() {
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState<'newest' | 'oldest'>('newest');
  const [contentType, setContentType] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const { data, isLoading, isError } = useQuery<PaginatedResponse<Content>>({
    queryKey: ['my-content', page, sortBy, contentType, status],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, limit: 9, sortBy };
      if (contentType) params.contentType = contentType;
      if (status) params.status = status;

      const response = await apiClient.get<PaginatedResponse<Content>>('/content/me', { params });
      return response.data;
    },
  });

  const handlePrevPage = () => {
    setPage((prev) => Math.max(prev - 1, 1));
  };

  const handleNextPage = () => {
    if (data && page < data.pagination.pages) {
      setPage((prev) => prev + 1);
    }
  };

  return (
    <section className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Evidence Library</h1>
          <p className="text-gray-400">Manage and view your registered evidence files.</p>
        </div>
        <Link
          to="/content/new"
          className="rounded-lg bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-gray-900 transition hover:bg-emerald-300 self-start sm:self-center"
        >
          Upload Evidence
        </Link>
      </div>

      {/* Filter and Sort Toolbar */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-gray-800 bg-gray-900/30 p-4">
        <div className="flex items-center gap-1 text-sm text-gray-400 pr-2 border-r border-gray-800">
          <Filter className="h-4 w-4" />
          <span>Filters</span>
        </div>

        {/* Content Type Selector */}
        <select
          value={contentType}
          onChange={(e) => { setContentType(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-emerald-500"
        >
          <option value="">All Types</option>
          <option value="text">Text</option>
          <option value="image">Image</option>
          <option value="document">Document</option>
          <option value="video">Video</option>
          <option value="audio">Audio</option>
        </select>

        {/* Status Selector */}
        <select
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-emerald-500"
        >
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="verified">Verified</option>
          <option value="flagged">Flagged</option>
          <option value="rejected">Rejected</option>
        </select>

        {/* Sort Selector */}
        <select
          value={sortBy}
          onChange={(e) => { setSortBy(e.target.value as 'newest' | 'oldest'); setPage(1); }}
          className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-xs text-gray-300 outline-none focus:border-emerald-500 ml-auto"
        >
          <option value="newest">Sort: Newest</option>
          <option value="oldest">Sort: Oldest</option>
        </select>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-20 text-gray-400 space-y-4">
          <div className="h-10 w-10 border-4 border-emerald-400 border-t-transparent rounded-full animate-spin" />
          <span>Fetching evidence registry...</span>
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-8 text-center text-red-400">
          Failed to load evidence library. Please try again.
        </div>
      ) : !data || data.contents.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-gray-800 bg-gray-900/10 p-20 text-center space-y-4">
          <Layers className="h-12 w-12 mx-auto text-gray-700" />
          <div className="space-y-1">
            <p className="font-semibold text-white">No registered evidence found</p>
            <p className="text-sm text-gray-500">You haven't added any files to the V-Trace network with these filters.</p>
          </div>
          <Link
            to="/content/new"
            className="inline-block rounded-lg border border-gray-700 hover:border-gray-500 px-4 py-2 text-sm font-semibold text-white"
          >
            Upload Your First File
          </Link>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Grid Layout */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {data.contents.map((item) => (
              <article
                key={item._id}
                className="flex flex-col justify-between rounded-xl border border-gray-800 bg-gray-900/30 p-5 backdrop-blur-sm transition hover:border-gray-700 hover:bg-gray-900/50"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs text-gray-400 bg-gray-950 px-2.5 py-1 rounded-full border border-gray-800 font-medium capitalize">
                      {getFileTypeIcon(item.contentType)}
                      <span>{item.contentType}</span>
                    </div>
                    {getStatusBadge(item.status)}
                  </div>

                  <h2 className="text-lg font-bold text-white line-clamp-1">{item.title}</h2>
                  
                  <div className="space-y-1.5 text-xs text-gray-500 font-mono">
                    <span className="block text-gray-500 font-sans font-normal">Original Hash</span>
                    <span className="block truncate bg-gray-950/50 p-2 rounded text-[10px] border border-gray-900">{item.originalHash}</span>
                  </div>
                </div>

                <div className="mt-5 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400">
                  <div className="flex items-center gap-1">
                    <Calendar className="h-3.5 w-3.5 text-gray-500" />
                    <span>{new Date(item.createdAt).toLocaleDateString()}</span>
                  </div>
                  <Link
                    to={`/content/${item._id}`}
                    className="font-semibold text-emerald-400 hover:text-emerald-300"
                  >
                    View Details
                  </Link>
                </div>
              </article>
            ))}
          </div>

          {/* Pagination Controls */}
          {data.pagination.pages > 1 && (
            <div className="flex items-center justify-between border-t border-gray-800 pt-4 text-sm">
              <span className="text-gray-400">
                Page {page} of {data.pagination.pages} ({data.pagination.total} items)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handlePrevPage}
                  disabled={page === 1}
                  className="inline-flex items-center justify-center p-2 rounded-lg border border-gray-800 text-gray-400 transition hover:bg-gray-900 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  onClick={handleNextPage}
                  disabled={page === data.pagination.pages}
                  className="inline-flex items-center justify-center p-2 rounded-lg border border-gray-800 text-gray-400 transition hover:bg-gray-900 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default ContentListPage;
