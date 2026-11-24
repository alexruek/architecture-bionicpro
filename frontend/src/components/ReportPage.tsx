import React, { useCallback, useEffect, useRef, useState } from 'react';
import { apiGet, fetchSession, login, logout, SessionUser } from '../api';

const ReportPage: React.FC = () => {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [initialized, setInitialized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const checked = useRef(false);

  const loadSession = useCallback(async () => {
    try {
      setUser(await fetchSession());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setInitialized(true);
    }
  }, []);

  useEffect(() => {
    // Один запрос при старте: каждое обращение ротирует session id.
    if (checked.current) {
      return;
    }
    checked.current = true;
    const params = new URLSearchParams(window.location.search);
    const authError = params.get('auth_error');
    if (authError) {
      setError(`Login failed: ${authError}`);
      window.history.replaceState(null, '', window.location.pathname);
    }
    loadSession();
  }, [loadSession]);

  const downloadReport = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiGet('/reports');
      if (response.status === 401) {
        setUser(null);
        setError('Session expired, please log in again');
        return;
      }
      if (!response.ok) {
        throw new Error(`Report request failed: ${response.status}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    setUser(null);
  };

  if (!initialized) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 gap-3">
        <button
          onClick={() => login()}
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
        >
          Login
        </button>
        <button
          onClick={() => login('yandex')}
          className="px-4 py-2 bg-yellow-400 text-black rounded hover:bg-yellow-500"
        >
          Login with Yandex ID
        </button>
        {error && <div className="mt-4 p-4 bg-red-100 text-red-700 rounded">{error}</div>}
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <div className="p-8 bg-white rounded-lg shadow-md">
        <h1 className="text-2xl font-bold mb-2">Usage Reports</h1>
        <p className="mb-6 text-gray-600">Signed in as {user.username}</p>

        <div className="flex gap-3">
          <button
            onClick={downloadReport}
            disabled={loading}
            className={`px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 ${
              loading ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            {loading ? 'Generating Report...' : 'Download Report'}
          </button>
          <button
            onClick={handleLogout}
            className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300"
          >
            Logout
          </button>
        </div>

        {error && (
          <div className="mt-4 p-4 bg-red-100 text-red-700 rounded">
            {error}
          </div>
        )}
      </div>
    </div>
  );
};

export default ReportPage;
