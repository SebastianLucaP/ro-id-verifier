import { useState } from 'react'
import './index.css'

function App() {
  const [pin, setPin] = useState('')
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState(null) // 'success' | 'error' | null

  const [user, setUser] = useState(null) // { name: string, serial: string }
  const [pemFile, setPemFile] = useState(null)
  const [pemContent, setPemContent] = useState(null)

  const addLog = (msg, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString()
    setLogs(prev => [`[${timestamp}] [${type.toUpperCase()}] ${msg}`, ...prev])
  }

  const handleFileChange = (e) => {
    const file = e.target.files[0]
    if (file) {
      setPemFile(file)
      const reader = new FileReader()
      reader.onload = (event) => {
        setPemContent(event.target.result)
        addLog(`Wallet loaded: ${file.name}`, 'info')
      }
      reader.readAsText(file)
    }
  }

  const handleAction = async (endpoint, actionName) => {
    if (!pin) {
      addLog("PIN is required!", 'error')
      setStatus('error')
      return
    }

    setLoading(true)
    setStatus(null)
    addLog(`Starting ${actionName}...`, 'info')

    try {
      const payload = { pin }
      if (pemContent) {
        payload.pemContent = pemContent
        addLog("Using custom wallet file...", 'info')
      }
      const response = await fetch(`http://localhost:5000/api/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const data = await response.json()

      if (response.ok) {
        addLog(`Success: ${data.message || 'Operation successful'}`, 'success')
        if (data.serial) addLog(`Serial: ${data.serial}`, 'info')
        if (data.serial_hash) addLog(`Hash: ${data.serial_hash.substring(0, 20)}...`, 'info')

        if (data.name && endpoint === 'login') {
          setUser({ name: data.name, serial: data.serial })
        }

        setStatus('success')

        if (endpoint === 'delete') {
          setUser(null)
          addLog("Logged out due to account deletion", 'info')
        }
      } else {
        addLog(`Error: ${data.error || 'Unknown error'}`, 'error')
        setStatus('error')
      }
    } catch (err) {
      addLog(`Network Error: ${err.message}`, 'error')
      setStatus('error')
    } finally {
      setLoading(false)
      // Enforce fresh upload for next action
      setPemFile(null)
      setPemContent(null)
      const fileInput = document.getElementById('wallet-upload')
      if (fileInput) fileInput.value = ''
    }
  }

  const handleLogout = () => {
    setUser(null)
    setPin('')
    setLogs([])
    setStatus(null)
  }

  if (user) {
    return (
      <div className="container">
        <div className="card">
          <h1>Welcome, {user.name}!</h1>
          <div className="status-indicator">
            <span className="badge success">Identity Verified</span>
          </div>

          <div className="user-details">
            <p><strong>Serial Number:</strong> {user.serial}</p>
            <p><strong>Status:</strong> Authenticated On-Chain</p>
          </div>

          <div className="button-grid" style={{ marginTop: '2rem' }}>
            <button
              className="btn btn-danger"
              onClick={handleLogout}
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="container">
      <div className="card">
        <h1>ID Verifier</h1>
        <div className="status-indicator">
          {loading ? <span className="badge loading">Processing...</span> :
            status === 'success' ? <span className="badge success">Ready (Last: Success)</span> :
              status === 'error' ? <span className="badge error">Ready (Last: Error)</span> :
                <span className="badge">Ready</span>}
        </div>

        <div className="input-group">
          <label>ID Card PIN</label>
          <input
            type="password"
            placeholder="Enter PIN"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            disabled={loading}
          />
        </div>

        <div className="input-group">
          <label>Wallet PEM (Required)</label>
          <input
            id="wallet-upload"
            type="file"
            accept=".pem"
            onChange={handleFileChange}
            disabled={loading}
            style={{ fontSize: '0.8rem' }}
          />
          {pemFile && <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '0.2rem' }}>Selected: {pemFile.name}</div>}
        </div>

        <div className="button-grid">
          <button
            className="btn btn-primary"
            onClick={() => handleAction('register', 'Registration')}
            disabled={loading || !pemFile}
          >
            Register Account
          </button>

          <button
            className="btn btn-success"
            onClick={() => handleAction('login', 'Login')}
            disabled={loading || !pemFile}
          >
            Authenticate (Login)
          </button>

          <button
            className="btn btn-danger"
            onClick={() => handleAction('delete', 'Deletion')}
            disabled={loading || !pemFile}
          >
            Delete Account
          </button>
        </div>
      </div>

      <div className="logs-panel">
        <h3>System Logs</h3>
        <div className="logs-content">
          {logs.length === 0 ? <div className="log-placeholder">Waiting for actions...</div> :
            logs.map((log, i) => (
              <div key={i} className={`log-entry ${log.includes('[ERROR]') ? 'log-error' : log.includes('[SUCCESS]') ? 'log-success' : ''}`}>
                {log}
              </div>
            ))
          }
        </div>
      </div>
    </div>
  )
}

export default App
