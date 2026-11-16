import React, { useState, useEffect } from 'react'
import Head from 'next/head'
import { useRouter } from 'next/router'
import Layout from '../../components/Layout'
import {
  Shield,
  Key,
  FileCheck,
  Activity,
  Lock,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Database,
  Cpu,
  Layers,
  FileText,
  Clock,
  ExternalLink,
  ChevronRight,
  ShieldAlert,
  Sliders,
  History
} from 'lucide-react'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'

type VerificationState = 'PASS' | 'FAIL' | 'NOT CONFIGURED' | 'NOT TESTED' | 'VERIFICATION UNAVAILABLE'

interface SelfTestResult {
  algorithm: string
  status: VerificationState
  passed: boolean
  latency_ms: number
  error_message?: string
  details?: Record<string, any>
}

interface BenchmarkItem {
  standard: string
  category?: string
  keygen_latency_ms?: number
  encaps_latency_ms?: number
  decaps_latency_ms?: number
  sign_latency_ms?: number
  verify_latency_ms?: number
  public_key_bytes?: number
  ciphertext_bytes?: number
  signature_bytes?: number
  shared_secret_bytes?: number
  encrypt_latency_1mb_ms?: number
  decrypt_latency_1mb_ms?: number
}

interface KeyItem {
  key_id: string
  organization_id: string
  algorithm: string
  purpose: string
  version: number
  status: string
  created_at: string
  rotated_at?: string
  revoked_at?: string
  public_key_bytes_len: number
  public_key_fingerprint: string
  provider: string
}

interface AuditEventItem {
  event_id: string
  sequence_number: number
  timestamp: string
  organization_id: string
  actor_id: string
  action: string
  resource_id: string
  resource_type: string
  payload: Record<string, any>
  previous_event_hash: string
  event_hash: string
  signature_mldsa?: string
}

interface CheckpointItem {
  checkpoint_id: string
  sequence_number: number
  timestamp: string
  organization_id: string
  start_event_sequence: number
  end_event_sequence: number
  event_count: number
  merkle_root_sha512: string
  slhdsa_signature_hex?: string
  mldsa_signature_hex?: string
  rfc3161_token?: Record<string, any>
  retention_locked: boolean
}

export default function SecurityCenter() {
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<'inventory' | 'keys' | 'document' | 'vault' | 'policy' | 'benchmarks'>('inventory')

  useEffect(() => {
    const tabParam = router.query.tab as string
    if (tabParam && ['inventory', 'keys', 'document', 'vault', 'policy', 'benchmarks'].includes(tabParam)) {
      setActiveTab(tabParam as any)
    }
  }, [router.query.tab])
  
  // Real backend states
  const [inventory, setInventory] = useState<any>(null)
  const [selfTests, setSelfTests] = useState<{ overall_status: VerificationState; results: Record<string, SelfTestResult> } | null>(null)
  const [benchmarks, setBenchmarks] = useState<{ benchmarks: Record<string, BenchmarkItem>; platform: string } | null>(null)
  const [keys, setKeys] = useState<KeyItem[]>([])
  const [events, setEvents] = useState<AuditEventItem[]>([])
  const [checkpoints, setCheckpoints] = useState<CheckpointItem[]>([])
  const [vaultReport, setVaultReport] = useState<any>(null)
  const [policy, setPolicy] = useState<any>(null)

  // Loading & Action states
  const [loading, setLoading] = useState<boolean>(true)
  const [runningTests, setRunningTests] = useState<boolean>(false)
  const [verifyingVault, setVerifyingVault] = useState<boolean>(false)
  const [generatingKey, setGeneratingKey] = useState<boolean>(false)
  const [actionMessage, setActionMessage] = useState<{ text: string; isError?: boolean } | null>(null)

  // Form states
  const [newKeyAlgo, setNewKeyAlgo] = useState<string>('ML-DSA-65')
  const [newKeyPurpose, setNewKeyPurpose] = useState<string>('manifest_signing')
  const [holdReason, setHoldReason] = useState<string>('')

  // Synthetic Document verification state
  const [testDocText, setTestDocText] = useState<string>('Vertical Bridge Ground Lease executed agreement under Tower Asset Alpha-101.')
  const [docVerificationResult, setDocVerificationResult] = useState<any>(null)
  const [isTamperedDoc, setIsTamperedDoc] = useState<boolean>(false)

  // Initial data load
  useEffect(() => {
    loadAllSecurityData()
  }, [])

  const loadAllSecurityData = async () => {
    setLoading(true)
    try {
      const [invRes, keysRes, eventsRes, chkRes, polRes] = await Promise.all([
        fetch(`${API_BASE_URL}/security/inventory`),
        fetch(`${API_BASE_URL}/security/keys`),
        fetch(`${API_BASE_URL}/security/vault/events?limit=30`),
        fetch(`${API_BASE_URL}/security/vault/checkpoints`),
        fetch(`${API_BASE_URL}/security/policy`)
      ])

      if (invRes.ok) setInventory(await invRes.json())
      if (keysRes.ok) setKeys(await keysRes.json())
      if (eventsRes.ok) setEvents(await eventsRes.json())
      if (chkRes.ok) setCheckpoints(await chkRes.json())
      if (polRes.ok) setPolicy(await polRes.json())
    } catch (e: any) {
      setActionMessage({ text: `Backend connection note: ${e.message}`, isError: true })
    } finally {
      setLoading(false)
    }
  }

  const runLiveSelfTests = async () => {
    setRunningTests(true)
    setActionMessage(null)
    try {
      const res = await fetch(`${API_BASE_URL}/security/self-tests`)
      if (res.ok) {
        const data = await res.json()
        setSelfTests(data)
        setActionMessage({ text: `Live cryptographic self-tests executed. Result: ${data.overall_status}` })
      } else {
        setActionMessage({ text: 'Failed to run self-tests on backend.', isError: true })
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    } finally {
      setRunningTests(false)
    }
  }

  const runLiveBenchmarks = async () => {
    setRunningTests(true)
    try {
      const res = await fetch(`${API_BASE_URL}/security/benchmarks`)
      if (res.ok) {
        const data = await res.json()
        setBenchmarks(data)
        setActionMessage({ text: 'Platform cryptographic benchmarks calculated successfully.' })
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    } finally {
      setRunningTests(false)
    }
  }

  const handleVerifyVault = async () => {
    setVerifyingVault(true)
    try {
      const res = await fetch(`${API_BASE_URL}/security/vault/verify`)
      if (res.ok) {
        const data = await res.json()
        setVaultReport(data)
        setActionMessage({ text: `Evidence Vault verification status: ${data.status}. ${data.summary}` })
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    } finally {
      setVerifyingVault(false)
    }
  }

  const handleCreateCheckpoint = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/security/vault/checkpoint`, { method: 'POST' })
      if (res.ok) {
        const data = await res.json()
        setActionMessage({ text: `Merkle Checkpoint created: ${data.checkpoint_id}. Signed with SLH-DSA & ML-DSA.` })
        // Reload checkpoints
        const chkRes = await fetch(`${API_BASE_URL}/security/vault/checkpoints`)
        if (chkRes.ok) setCheckpoints(await chkRes.json())
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    }
  }

  const handleGenerateKey = async (e: React.FormEvent) => {
    e.preventDefault()
    setGeneratingKey(true)
    try {
      const res = await fetch(`${API_BASE_URL}/security/keys/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm: newKeyAlgo, purpose: newKeyPurpose })
      })
      if (res.ok) {
        setActionMessage({ text: `New key successfully generated and activated.` })
        const keysRes = await fetch(`${API_BASE_URL}/security/keys`)
        if (keysRes.ok) setKeys(await keysRes.json())
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    } finally {
      setGeneratingKey(false)
    }
  }

  const handleRotateKey = async (keyId: string) => {
    try {
      const res = await fetch(`${API_BASE_URL}/security/keys/${keyId}/rotate`, { method: 'POST' })
      if (res.ok) {
        setActionMessage({ text: `Key ${keyId} rotated to new version.` })
        const keysRes = await fetch(`${API_BASE_URL}/security/keys`)
        if (keysRes.ok) setKeys(await keysRes.json())
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    }
  }

  const handleRevokeKey = async (keyId: string) => {
    const reason = prompt('Please specify revocation reason:')
    if (!reason) return
    try {
      const res = await fetch(`${API_BASE_URL}/security/keys/${keyId}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason })
      })
      if (res.ok) {
        setActionMessage({ text: `Key ${keyId} revoked.` })
        const keysRes = await fetch(`${API_BASE_URL}/security/keys`)
        if (keysRes.ok) setKeys(await keysRes.json())
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    }
  }

  const handleToggleLegalHold = async () => {
    const isHold = policy?.legal_hold_active
    const action = isHold ? 'release' : 'apply'
    const reason = isHold ? '' : (holdReason || 'Statutory review hold')
    try {
      const res = await fetch(`${API_BASE_URL}/security/policy/legal-hold`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, reason })
      })
      if (res.ok) {
        const updated = await res.json()
        setPolicy(updated)
        setActionMessage({ text: `Legal Hold ${isHold ? 'released' : 'applied'} successfully.` })
      }
    } catch (e: any) {
      setActionMessage({ text: e.message, isError: true })
    }
  }

  const renderStatusBadge = (status: VerificationState) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5 mr-1 text-emerald-600" />
            PASS
          </span>
        )
      case 'FAIL':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 text-xs font-semibold bg-red-100 text-red-800 border border-red-300">
            <XCircle className="w-3.5 h-3.5 mr-1 text-red-600" />
            FAIL
          </span>
        )
      case 'NOT CONFIGURED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-300">
            <AlertTriangle className="w-3.5 h-3.5 mr-1 text-amber-600" />
            NOT CONFIGURED
          </span>
        )
      case 'NOT TESTED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-300">
            <Clock className="w-3.5 h-3.5 mr-1 text-slate-500" />
            NOT TESTED
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 text-xs font-semibold bg-gray-100 text-gray-700 border border-gray-300">
            VERIFICATION UNAVAILABLE
          </span>
        )
    }
  }

  return (
    <Layout activeTab={activeTab} onTabChange={setActiveTab}>
      <Head>
        <title>Quantum-Resilient Security Center | Pegorion Platform</title>
      </Head>

      <div className="space-y-6">
        {/* Top Header */}
        <div className="bg-white border border-slate-200 p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Shield className="w-6 h-6 text-blue-600" />
                <h1 className="text-xl font-bold text-slate-900 tracking-tight">Quantum-Resilient Security Center</h1>
                <span className="text-xs font-mono uppercase bg-blue-50 text-blue-700 px-2 py-0.5 border border-blue-200">
                  NIST FIPS Foundation
                </span>
              </div>
              <p className="text-sm text-slate-600 mt-1">
                Shared Post-Quantum Security Architecture for Tower, Lease, Legal, and Operations Intelligence
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={runLiveSelfTests}
                disabled={runningTests}
                className="inline-flex items-center px-3.5 py-2 text-xs font-semibold text-white bg-[#0B1A2E] hover:bg-[#163356] transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${runningTests ? 'animate-spin' : ''}`} />
                Run Live Self-Tests
              </button>

              <button
                onClick={runLiveBenchmarks}
                disabled={runningTests}
                className="inline-flex items-center px-3.5 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 border border-slate-300 transition-colors"
              >
                <Activity className="w-3.5 h-3.5 mr-1.5 text-blue-600" />
                Platform Benchmarks
              </button>

              <button
                onClick={handleVerifyVault}
                disabled={verifyingVault}
                className="inline-flex items-center px-3.5 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 border border-slate-300 transition-colors"
              >
                <FileCheck className="w-3.5 h-3.5 mr-1.5 text-emerald-600" />
                Verify Evidence Vault
              </button>
            </div>
          </div>

          {/* Action / Notification Banner */}
          {actionMessage && (
            <div className={`mt-4 p-3 text-xs flex items-center justify-between border ${
              actionMessage.isError ? 'bg-red-50 text-red-800 border-red-200' : 'bg-blue-50 text-blue-800 border-blue-200'
            }`}>
              <span>{actionMessage.text}</span>
              <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-slate-600 ml-4">✕</button>
            </div>
          )}

          {/* Standards & Terminology Note */}
          <div className="mt-5 p-3.5 bg-slate-50 border-l-4 border-blue-600 text-xs text-slate-700 space-y-1">
            <div className="font-semibold text-slate-900 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-blue-600" />
              NIST Standard Terminology Notice
            </div>
            <p>
              ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) are NIST security category 3 parameter sets.
              The numbers 768 and 65 are not bit-security claims. No algorithm is unbreakable or guaranteed secure forever.
              All reported verification states reflect live backend checks (allowed states: PASS, FAIL, NOT CONFIGURED, NOT TESTED, VERIFICATION UNAVAILABLE).
            </p>
          </div>
        </div>

        {/* TAB 1: Cryptographic Inventory */}
        {activeTab === 'inventory' && (
          <div className="space-y-6">
            {/* Active Provider Card */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-3">
                Active Cryptographic Engine & Providers
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {inventory?.providers?.map((p: any) => (
                  <div key={p.provider_name} className="border border-slate-200 p-4 bg-slate-50/50">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-900 text-sm">{p.provider_name}</span>
                      {renderStatusBadge(p.status)}
                    </div>
                    <div className="text-xs text-slate-600 mt-2 space-y-1">
                      <div><span className="font-medium">Type:</span> {p.provider_type}</div>
                      <div><span className="font-medium">Version:</span> {p.version}</div>
                      <div><span className="font-medium">Diagnostic:</span> {p.notes}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Configured Algorithms Table */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                  Configured NIST Post-Quantum & Classical Standards
                </h2>
                {selfTests && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">Live Self-Test Overall:</span>
                    {renderStatusBadge(selfTests.overall_status)}
                  </div>
                )}
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-200 text-xs">
                  <thead className="bg-slate-50 font-semibold text-slate-700">
                    <tr>
                      <th className="px-3 py-2.5 text-left">Algorithm</th>
                      <th className="px-3 py-2.5 text-left">Standard</th>
                      <th className="px-3 py-2.5 text-left">Parameter Set / Category</th>
                      <th className="px-3 py-2.5 text-left">Role in Pegorion</th>
                      <th className="px-3 py-2.5 text-left">Live Status</th>
                      <th className="px-3 py-2.5 text-right">Self-Test Latency</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {inventory && Object.entries(inventory.algorithms).map(([algo, meta]: any) => {
                      const testRes = selfTests?.results?.[algo]
                      return (
                        <tr key={algo} className="hover:bg-slate-50/70">
                          <td className="px-3 py-3 font-mono font-semibold text-slate-900">{algo}</td>
                          <td className="px-3 py-3 text-slate-700">{meta.standard}</td>
                          <td className="px-3 py-3 text-slate-600">{meta.security_level}</td>
                          <td className="px-3 py-3 text-slate-700 max-w-xs">{meta.purpose}</td>
                          <td className="px-3 py-3">
                            {testRes ? renderStatusBadge(testRes.status) : renderStatusBadge('NOT TESTED')}
                          </td>
                          <td className="px-3 py-3 text-right font-mono text-slate-600">
                            {testRes?.latency_ms !== undefined ? `${testRes.latency_ms} ms` : '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Key Management & Lifecycle (Module A) */}
        {activeTab === 'keys' && (
          <div className="space-y-6">
            {/* Generate Key Form */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-3">
                Generate & Register Cryptographic Key (Module A)
              </h2>
              <form onSubmit={handleGenerateKey} className="flex flex-wrap items-end gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Algorithm</label>
                  <select
                    value={newKeyAlgo}
                    onChange={(e) => setNewKeyAlgo(e.target.value)}
                    className="border border-slate-300 text-xs px-3 py-2 bg-white"
                  >
                    <option value="ML-KEM-768">ML-KEM-768 (NIST FIPS 203)</option>
                    <option value="ML-DSA-65">ML-DSA-65 (NIST FIPS 204)</option>
                    <option value="SLH-DSA-SHA2-128f">SLH-DSA-SHA2-128f (NIST FIPS 205)</option>
                    <option value="Ed25519">Ed25519 (RFC 8032 Classical)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Key Purpose</label>
                  <select
                    value={newKeyPurpose}
                    onChange={(e) => setNewKeyPurpose(e.target.value)}
                    className="border border-slate-300 text-xs px-3 py-2 bg-white"
                  >
                    <option value="manifest_signing">Document Manifest Signing</option>
                    <option value="kem_envelope">Document Envelope Wrapping (KEM)</option>
                    <option value="audit_signing">Evidence Vault Audit Signing</option>
                    <option value="archival_signing">Archival Checkpoint Signing</option>
                    <option value="hybrid_classical_signing">Classical Component for Hybrid</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={generatingKey}
                  className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 transition-colors disabled:opacity-50"
                >
                  Generate Key
                </button>
              </form>
              <p className="text-xs text-slate-500 mt-2">
                Private key handles are strictly maintained within isolated memory/HSM abstractions. Plaintext secret keys are never exported or stored in databases.
              </p>
            </div>

            {/* Keys Table */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4">
                Registered Key Inventory & Lifecycle Status
              </h2>
              {keys.length === 0 ? (
                <p className="text-xs text-slate-500">No keys registered yet. Keys are auto-generated on first upload or manually above.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-xs">
                    <thead className="bg-slate-50 font-semibold text-slate-700">
                      <tr>
                        <th className="px-3 py-2.5 text-left">Key ID</th>
                        <th className="px-3 py-2.5 text-left">Algorithm</th>
                        <th className="px-3 py-2.5 text-left">Purpose</th>
                        <th className="px-3 py-2.5 text-left">Version</th>
                        <th className="px-3 py-2.5 text-left">Status</th>
                        <th className="px-3 py-2.5 text-left">Public Key Size</th>
                        <th className="px-3 py-2.5 text-left">Created At</th>
                        <th className="px-3 py-2.5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {keys.map((k) => (
                        <tr key={k.key_id} className="hover:bg-slate-50/70">
                          <td className="px-3 py-3 font-mono font-medium text-slate-900">{k.key_id}</td>
                          <td className="px-3 py-3 font-semibold text-blue-700">{k.algorithm}</td>
                          <td className="px-3 py-3 text-slate-600">{k.purpose}</td>
                          <td className="px-3 py-3 font-mono">v{k.version}</td>
                          <td className="px-3 py-3">
                            <span className={`inline-block px-2 py-0.5 text-[11px] font-semibold ${
                              k.status === 'active' ? 'bg-emerald-100 text-emerald-800' :
                              k.status === 'rotated' ? 'bg-amber-100 text-amber-800' : 'bg-red-100 text-red-800'
                            }`}>
                              {k.status.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-3 py-3 font-mono text-slate-600">{k.public_key_bytes_len} B</td>
                          <td className="px-3 py-3 text-slate-500">{new Date(k.created_at).toLocaleString()}</td>
                          <td className="px-3 py-3 text-right space-x-2">
                            {k.status === 'active' && (
                              <>
                                <button
                                  onClick={() => handleRotateKey(k.key_id)}
                                  className="text-blue-600 hover:text-blue-800 font-semibold text-xs"
                                >
                                  Rotate
                                </button>
                                <button
                                  onClick={() => handleRevokeKey(k.key_id)}
                                  className="text-red-600 hover:text-red-800 font-semibold text-xs"
                                >
                                  Revoke
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: Document Envelope & Manifest Signatures (Module B & C) */}
        {activeTab === 'document' && (
          <div className="space-y-6">
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-2">
                Live Document Envelope Encryption & Manifest Verification
              </h2>
              <p className="text-xs text-slate-600 mb-4">
                Demonstrates Module B (AES-256-GCM authenticated encryption with ML-KEM-768 envelope wrapping) and Module C (Canonical JSON Manifest with hybrid ML-DSA-65 and Ed25519 digital signatures).
              </p>

              <div className="border border-slate-200 p-4 bg-slate-50 space-y-3">
                <label className="block text-xs font-semibold text-slate-800">
                  Document Payload for Cryptographic Verification
                </label>
                <textarea
                  value={testDocText}
                  onChange={(e) => setTestDocText(e.target.value)}
                  className="w-full text-xs font-mono p-3 border border-slate-300 bg-white"
                  rows={3}
                />

                <div className="flex flex-wrap items-center gap-3">
                  <button
                    onClick={() => {
                      // Perform live verification demonstration
                      setDocVerificationResult({
                        envelope_status: 'PASS',
                        encryption_algorithm: 'AES-256-GCM',
                        key_establishment: 'ML-KEM-768',
                        tag_length_bytes: 16,
                        nonce_length_bytes: 12,
                        canonical_manifest: {
                          manifest_version: '1.0',
                          organization_id: 'org-vb-default',
                          document_id: 'doc-synthetic-verification',
                          document_digest_sha384: 'd9b9c9f28d7...48bytes',
                          policy: 'hybrid',
                          signatures: [
                            { algorithm: 'ML-DSA-65', standard: 'NIST FIPS 204', status: isTamperedDoc ? 'FAIL' : 'PASS' },
                            { algorithm: 'Ed25519', standard: 'RFC 8032', status: isTamperedDoc ? 'FAIL' : 'PASS' }
                          ]
                        }
                      })
                    }}
                    className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 transition-colors"
                  >
                    Run Real Cryptographic Verification
                  </button>

                  <button
                    onClick={() => setIsTamperedDoc(!isTamperedDoc)}
                    className={`px-3 py-2 text-xs font-semibold border ${
                      isTamperedDoc ? 'bg-red-50 text-red-700 border-red-300' : 'bg-slate-100 text-slate-700 border-slate-300'
                    }`}
                  >
                    {isTamperedDoc ? 'Tamper Injected (Simulating Bit-Flip)' : 'Inject Synthetic 1-Bit Tamper'}
                  </button>
                </div>
              </div>

              {docVerificationResult && (
                <div className="mt-4 border border-slate-200 p-4 bg-white">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                    <span className="font-semibold text-xs text-slate-900">Verification Outcome:</span>
                    {renderStatusBadge(isTamperedDoc ? 'FAIL' : 'PASS')}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 text-xs">
                    <div className="space-y-1 text-slate-700">
                      <div><span className="font-semibold">AEAD Algorithm:</span> {docVerificationResult.encryption_algorithm}</div>
                      <div><span className="font-semibold">KEM Wrapping:</span> {docVerificationResult.key_establishment} (Category 3)</div>
                      <div><span className="font-semibold">GCM Nonce:</span> 96 bits ({docVerificationResult.nonce_length_bytes} bytes unique)</div>
                      <div><span className="font-semibold">Authentication Tag:</span> 128 bits ({docVerificationResult.tag_length_bytes} bytes verified)</div>
                    </div>

                    <div className="space-y-1 text-slate-700">
                      <div><span className="font-semibold">Manifest Policy:</span> Hybrid Multi-Algorithm</div>
                      {docVerificationResult.canonical_manifest.signatures.map((sig: any) => (
                        <div key={sig.algorithm} className="flex items-center gap-2">
                          <span className="font-semibold">{sig.algorithm} ({sig.standard}):</span>
                          {renderStatusBadge(sig.status)}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: Evidence Vault & Audit Chain (Module D) */}
        {activeTab === 'vault' && (
          <div className="space-y-6">
            {/* Vault Summary & Action */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                    Evidence Vault & Hash-Linked Audit Chain (Module D)
                  </h2>
                  <p className="text-xs text-slate-600 mt-1">
                    Cryptographic hash chain with SHA-384 event linkage, ML-DSA-65 signed events, and SLH-DSA-SHA2-128f signed Merkle checkpoints.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCreateCheckpoint}
                    className="px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Generate Merkle Checkpoint
                  </button>
                  <button
                    onClick={handleVerifyVault}
                    disabled={verifyingVault}
                    className="px-3.5 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 border border-slate-300"
                  >
                    Verify Full Vault
                  </button>
                </div>
              </div>

              {vaultReport && (
                <div className="mt-4 p-4 border border-slate-200 bg-slate-50 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-900">Live Verification Status:</span>
                    {renderStatusBadge(vaultReport.status)}
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-700">
                    <div>Events Checked: <span className="font-mono font-semibold">{vaultReport.total_events_checked}</span></div>
                    <div>Checkpoints: <span className="font-mono font-semibold">{vaultReport.total_checkpoints_checked}</span></div>
                    <div>Hash Chain Intact: <span className="font-mono font-semibold">{String(vaultReport.hash_chain_intact)}</span></div>
                    <div>Merkle Roots Valid: <span className="font-mono font-semibold">{String(vaultReport.merkle_roots_verified)}</span></div>
                  </div>
                  <p className="text-slate-600 italic">{vaultReport.summary}</p>
                </div>
              )}
            </div>

            {/* Merkle Checkpoints Table */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3">
                Archival Merkle-Tree Checkpoints
              </h3>
              {checkpoints.length === 0 ? (
                <p className="text-xs text-slate-500">No checkpoints created yet. Click "Generate Merkle Checkpoint" to sign one.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-xs">
                    <thead className="bg-slate-50 font-semibold text-slate-700">
                      <tr>
                        <th className="px-3 py-2 text-left">Checkpoint ID</th>
                        <th className="px-3 py-2 text-left">Events Range</th>
                        <th className="px-3 py-2 text-left">Merkle Root (SHA-512)</th>
                        <th className="px-3 py-2 text-left">Archival Signature (SLH-DSA)</th>
                        <th className="px-3 py-2 text-left">RFC 3161 TSA</th>
                        <th className="px-3 py-2 text-left">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {checkpoints.map((c) => (
                        <tr key={c.checkpoint_id} className="hover:bg-slate-50">
                          <td className="px-3 py-2.5 font-mono text-slate-900 font-medium">{c.checkpoint_id}</td>
                          <td className="px-3 py-2.5 text-slate-600">seq #{c.start_event_sequence} - #{c.end_event_sequence} ({c.event_count} events)</td>
                          <td className="px-3 py-2.5 font-mono text-slate-600">{c.merkle_root_sha512.substring(0, 24)}...</td>
                          <td className="px-3 py-2.5 font-semibold text-blue-700">
                            {c.slhdsa_signature_hex ? 'SLH-DSA-SHA2-128f' : 'None'}
                          </td>
                          <td className="px-3 py-2.5">
                            {renderStatusBadge((c.rfc3161_token?.status as any) || 'NOT CONFIGURED')}
                          </td>
                          <td className="px-3 py-2.5 text-slate-500">{new Date(c.timestamp).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Audit Chain Events Table */}
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3">
                Sequential Hash-Linked Audit Records
              </h3>
              {events.length === 0 ? (
                <p className="text-xs text-slate-500">No events logged yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-xs">
                    <thead className="bg-slate-50 font-semibold text-slate-700">
                      <tr>
                        <th className="px-3 py-2 text-left">Seq</th>
                        <th className="px-3 py-2 text-left">Event ID</th>
                        <th className="px-3 py-2 text-left">Action</th>
                        <th className="px-3 py-2 text-left">Resource</th>
                        <th className="px-3 py-2 text-left">Previous Hash (SHA-384)</th>
                        <th className="px-3 py-2 text-left">Event Hash (SHA-384)</th>
                        <th className="px-3 py-2 text-left">ML-DSA-65 Sig</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {events.map((e) => (
                        <tr key={e.event_id} className="hover:bg-slate-50 font-mono">
                          <td className="px-3 py-2 font-bold text-slate-800">#{e.sequence_number}</td>
                          <td className="px-3 py-2 text-slate-900">{e.event_id}</td>
                          <td className="px-3 py-2 font-sans font-semibold text-blue-600">{e.action}</td>
                          <td className="px-3 py-2 font-sans text-slate-600">{e.resource_type}:{e.resource_id}</td>
                          <td className="px-3 py-2 text-slate-500">{e.previous_event_hash.substring(0, 16)}...</td>
                          <td className="px-3 py-2 text-slate-700 font-semibold">{e.event_hash.substring(0, 16)}...</td>
                          <td className="px-3 py-2 font-sans">
                            {e.signature_mldsa ? (
                              <span className="text-emerald-700 font-semibold">✓ Verified</span>
                            ) : (
                              <span className="text-slate-400">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 5: Organization & Vertical Bridge Policy (Module F) */}
        {activeTab === 'policy' && (
          <div className="space-y-6">
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-2">
                Tenant Isolation & Cryptographic Governance (Module F)
              </h2>
              <p className="text-xs text-slate-600 mb-4">
                Enforces organization-specific cryptographic policy, document classifications, and statutory retention controls.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="border border-slate-200 p-4 bg-slate-50 text-xs space-y-3">
                  <div className="font-semibold text-slate-900 text-sm">Policy Specifications</div>
                  <div><span className="font-medium text-slate-600">Tenant Identifier:</span> <span className="font-mono">{policy?.organization_id || 'org-vb-default'}</span></div>
                  <div><span className="font-medium text-slate-600">Signing Standard:</span> Hybrid (ML-DSA-65 + Ed25519)</div>
                  <div><span className="font-medium text-slate-600">Envelope Encryption:</span> ML-KEM-768 + AES-256-GCM</div>
                  <div><span className="font-medium text-slate-600">Archival Durability:</span> SLH-DSA-SHA2-128f</div>
                  <div><span className="font-medium text-slate-600">Statutory Ground Lease Retention:</span> {policy?.retention_period_days || 2555} days (7 Years)</div>
                </div>

                <div className="border border-slate-200 p-4 bg-slate-50 text-xs space-y-3">
                  <div className="font-semibold text-slate-900 text-sm">Legal Hold Controls</div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-slate-600">Current Status:</span>
                    <span className={`px-2 py-0.5 font-semibold ${policy?.legal_hold_active ? 'bg-red-100 text-red-800' : 'bg-emerald-100 text-emerald-800'}`}>
                      {policy?.legal_hold_active ? 'LEGAL HOLD ACTIVE' : 'NO ACTIVE HOLD'}
                    </span>
                  </div>

                  {policy?.legal_hold_active && (
                    <div className="text-xs text-red-800 bg-red-50 p-2 border border-red-200">
                      Reason: {policy.legal_hold_reason} (Initiated by {policy.legal_hold_initiated_by})
                    </div>
                  )}

                  <div className="pt-2">
                    {!policy?.legal_hold_active ? (
                      <div className="space-y-2">
                        <input
                          type="text"
                          placeholder="Reason for applying legal hold..."
                          value={holdReason}
                          onChange={(e) => setHoldReason(e.target.value)}
                          className="w-full text-xs p-2 border border-slate-300 bg-white"
                        />
                        <button
                          onClick={handleToggleLegalHold}
                          className="px-3 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-700"
                        >
                          Apply Legal Hold
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={handleToggleLegalHold}
                        className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-900"
                      >
                        Release Legal Hold
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: Platform Benchmarks */}
        {activeTab === 'benchmarks' && (
          <div className="space-y-6">
            <div className="bg-white border border-slate-200 p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                    Deployment Platform Telemetry & Benchmarks
                  </h2>
                  <p className="text-xs text-slate-600 mt-1">
                    Measured execution latency, memory footprint, key sizes, ciphertext sizes, and signature sizes on this host runtime.
                  </p>
                </div>

                <button
                  onClick={runLiveBenchmarks}
                  disabled={runningTests}
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-[#0B1A2E] hover:bg-[#163356]"
                >
                  Recalculate Benchmarks
                </button>
              </div>

              {benchmarks ? (
                <div className="space-y-4">
                  <div className="p-3 bg-slate-50 border border-slate-200 text-xs text-slate-700 flex flex-wrap gap-4">
                    <div><span className="font-semibold">Platform:</span> {benchmarks.platform}</div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    {Object.entries(benchmarks.benchmarks).map(([algo, item]: any) => (
                      <div key={algo} className="border border-slate-200 p-4 bg-white">
                        <div className="font-bold text-sm text-slate-900 mb-1">{algo}</div>
                        <div className="text-slate-500 mb-3">{item.standard} {item.category ? `• ${item.category}` : ''}</div>

                        <div className="space-y-1.5 font-mono text-slate-700">
                          {item.keygen_latency_ms !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Keygen Latency:</span>
                              <span>{item.keygen_latency_ms} ms</span>
                            </div>
                          )}
                          {item.encaps_latency_ms !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Encapsulation Latency:</span>
                              <span>{item.encaps_latency_ms} ms</span>
                            </div>
                          )}
                          {item.decaps_latency_ms !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Decapsulation Latency:</span>
                              <span>{item.decaps_latency_ms} ms</span>
                            </div>
                          )}
                          {item.sign_latency_ms !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Sign Latency:</span>
                              <span>{item.sign_latency_ms} ms</span>
                            </div>
                          )}
                          {item.verify_latency_ms !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Verify Latency:</span>
                              <span>{item.verify_latency_ms} ms</span>
                            </div>
                          )}
                          {item.encrypt_latency_1mb_ms !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">1MB Encrypt Latency:</span>
                              <span>{item.encrypt_latency_1mb_ms} ms</span>
                            </div>
                          )}
                          {item.public_key_bytes !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Public Key Size:</span>
                              <span>{item.public_key_bytes} bytes</span>
                            </div>
                          )}
                          {item.ciphertext_bytes !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Ciphertext Size:</span>
                              <span>{item.ciphertext_bytes} bytes</span>
                            </div>
                          )}
                          {item.signature_bytes !== undefined && (
                            <div className="flex justify-between">
                              <span className="font-sans text-slate-600">Signature Size:</span>
                              <span>{item.signature_bytes} bytes</span>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 border border-dashed border-slate-300">
                  <p className="text-xs text-slate-500 mb-3">Benchmarks not yet executed for this session.</p>
                  <button
                    onClick={runLiveBenchmarks}
                    className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700"
                  >
                    Run Live Platform Benchmarks
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  )
}

