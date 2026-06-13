import { type FormEvent, useState } from 'react';
import apiClient from '../../lib/axios';
import type { Content, PaginatedResponse } from '../../types';

function getStatusClass(status: string) {
  if (status === 'verified') return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
  if (status === 'flagged') return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
  if (status === 'rejected') return 'bg-red-500/20 text-red-300 border-red-500/30';
  return 'bg-gray-500/20 text-gray-200 border-gray-500/30';
}

function PublicVerifyPage() {
  const [hash, setHash] = useState('');
  const [results, setResults] = useState<Content[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorMessage('');

    if (!/^[0-9a-fA-F]{64}$/.test(hash)) {
      setErrorMessage('Enter a valid 64-character SHA-256 hash');
      return;
    }

    setIsLoading(true);

    try {
      const response = await apiClient.get<PaginatedResponse<Content>>('/content', {
        params: { search: hash, page: 1, limit: 20 },
      });
      setResults(response.data.contents || []);
      setSearched(true);
    } catch {
      setErrorMessage('Unable to verify hash at this time');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="space-y-6">
      <h1 className="text-3xl font-semibold text-white">Verify Digital Evidence</h1>

      <form onSubmit={handleSubmit} className="space-y-3 rounded-xl border border-gray-800 bg-gray-900 p-5">
        <label htmlFor="hash" className="block text-sm text-gray-300">Evidence Hash (SHA-256)</label>
        <input
          id="hash"
          value={hash}
          onChange={(event) => setHash(event.target.value.trim())}
          placeholder="Enter 64-character evidence hash"
          className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none ring-emerald-400/40 focus:ring"
        />

        {errorMessage ? <p className="text-sm text-red-400">{errorMessage}</p> : null}

        <button
          type="submit"
          disabled={isLoading}
          className="rounded-md bg-emerald-400 px-4 py-2 text-sm font-semibold text-gray-900 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-70"
        >
          {isLoading ? 'Verifying...' : 'Verify'}
        </button>
      </form>

      {searched && (
        <div className="space-y-3">
          {results.length === 0 ? (
            <p className="rounded-md border border-gray-800 bg-gray-900 p-4 text-gray-300">
              No registered evidence found for this hash
            </p>
          ) : (
            results.map((item) => (
              <article key={item._id} className="rounded-xl border border-gray-800 bg-gray-900 p-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 className="text-lg font-semibold text-white">{item.title}</h2>
                  <span className={`rounded-full border px-3 py-1 text-xs font-medium ${getStatusClass(item.status)}`}>
                    {item.status}
                  </span>
                </div>
                <p className="mt-2 text-sm text-gray-400">Owner: {item.owner?.name || 'Unknown'}</p>
                <p className="text-sm text-gray-500">{new Date(item.createdAt).toLocaleString()}</p>
              </article>
            ))
          )}
        </div>
      )}
    </section>
  );
}

export default PublicVerifyPage;
