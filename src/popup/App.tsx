import './App.css';

export default function App() {
  return (
    <div style={{ width: '320px', padding: '16px', fontFamily: 'sans-serif' }}>
      <h2 style={{ margin: '0 0 8px 0', color: '#1a73e8' }}>SecureSense</h2>
      <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#555' }}>
        Website Security Scanner
      </p>
      <div
        style={{
          padding: '12px',
          borderRadius: '8px',
          backgroundColor: '#e8f0fe',
          color: '#1a73e8',
          fontSize: '13px',
          fontWeight: 500,
        }}
      >
        Status: Active & Ready
      </div>
    </div>
  );
}