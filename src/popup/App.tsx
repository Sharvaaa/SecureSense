import { useEffect, useState } from 'react';
import './App.css';

type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

interface UrlAnalysis {
  url: string;
  score: number;
  level: RiskLevel;
  reasons: string[];
}

function App() {
  const [analysis, setAnalysis] = useState<UrlAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    chrome.runtime.sendMessage(
      { type: 'GET_CURRENT_URL' },
      (response) => {
        if (chrome.runtime.lastError) {
          setError(
            chrome.runtime.lastError.message ||
            'An unkown extension error occurred.',
          );
        }

        if (!response?.success) {
          setError(response?.error || 'Unable to analyze the current website.');
          return;
        }

        setAnalysis(response.analysis);
      },
    );
  }, []);

  if (error) {
    return (
      <div
        style={{
          width: '320px',
          padding: '16px',
          fontFamily: 'sans-serif',
        }}
      >
        <h2 style={{ margin: '0 0 8px', color: '#1a73e8' }}>
          SecureSense
        </h2>

        <p
          style={{
            margin: '0 0 16px',
            fontSize: '13px',
            color: '#555',
          }}
        >
          Website Security Scanner
        </p>

        <div
          style={{
            padding: '12px',
            borderRadius: '8px',
            backgroundColor: '#ffebee',
            color: '#c62828',
            fontSize: '13px',
          }}
        >
          {error}
        </div>
      </div>
    );
  }

  if (!analysis) {
    return (
      <div
        style={{
          width: '320px',
          padding: '16px',
          fontFamily: 'sans-serif',
        }}
      >
        <h2 style={{ margin: '0 0 8px', color: '#1a73e8' }}>
          SecureSense
        </h2>

        <p
          style={{
            margin: '0 0 16px',
            fontSize: '13px',
            color: '#555',
          }}
        >
          Website Security Scanner
        </p>

        <div
          style={{
            padding: '12px',
            borderRadius: '8px',
            backgroundColor: '#f5f5f5',
            fontSize: '13px',
            textAlign: 'center',
          }}
        >
          Scanning current website...
        </div>
      </div>
    );
  }

  const levelClass = analysis.level.toLowerCase();

  return (
    <div
      style={{
        width: '320px',
        padding: '16px',
        fontFamily: 'sans-serif',
      }}
    >
      <h2
        style={{
          margin: '0 0 8px',
          color: '#1a73e8',
        }}
      >
        SecureSense
      </h2>

      <p
        style={{
          margin: '0 0 16px',
          fontSize: '13px',
          color: '#555',
        }}
      >
        Website Security Scanner
      </p>

      <div
        className={`risk-card ${levelClass}`}
        style={{
          padding: '16px',
          borderRadius: '10px',
          textAlign: 'center',
          marginBottom: '16px',
        }}
      >
        <div
          style={{
            fontSize: '12px',
            fontWeight: 600,
            marginBottom: '4px',
          }}
        >
          RISK SCORE
        </div>

        <div
          style={{
            fontSize: '36px',
            fontWeight: 700,
          }}
        >
          {analysis.score}
          <span style={{ fontSize: '16px' }}>/100</span>
        </div>

        <div
          style={{
            marginTop: '4px',
            fontSize: '14px',
            fontWeight: 700,
          }}
        >
          {analysis.level}
        </div>
      </div>

      <div
        style={{
          padding: '12px',
          borderRadius: '8px',
          backgroundColor: '#f5f5f5',
          wordBreak: 'break-all',
          fontSize: '12px',
          marginBottom: '16px',
        }}
      >
        <strong>Current website:</strong>
        <br />
        {analysis.url}
      </div>

      <div>
        <strong style={{ fontSize: '14px' }}>
          Security analysis
        </strong>

        {analysis.reasons.length === 0 ? (
          <p
            style={{
              fontSize: '13px',
              color: '#2e7d32',
            }}
          >
            No suspicious characteristics detected.
          </p>
        ) : (
          <ul
            style={{
              paddingLeft: '20px',
              marginTop: '8px',
              fontSize: '12px',
            }}
          >
            {analysis.reasons.map((reason, index) => (
              <li key={index} style={{ marginBottom: '7px' }}>
                {reason}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default App;