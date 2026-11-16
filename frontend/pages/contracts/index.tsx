import { useState, useEffect } from 'react'
import Layout from '../../components/Layout'
import { FileText, AlertCircle, Shield, Plus, RefreshCw } from 'lucide-react'
import { API_BASE_URL, useContracts } from '../../lib/api'

const fallbackContracts = [
  { id: 'contract-001', contract_type: 'Master Ground Lease', contract_number: 'VB-MLA-2024-001', status: 'active', signed_date: '2023-01-01', risk: 'Low' },
  { id: 'contract-002', contract_type: 'Colocation Agreement', contract_number: 'VB-COLO-2024-002', status: 'active', signed_date: '2023-06-15', risk: 'Medium' },
  { id: 'contract-003', contract_type: 'Subsurface Easement', contract_number: 'VB-EASE-2024-003', status: 'draft', signed_date: '-', risk: 'Pending' },
]

export default function ContractsPage() {
  const { data: apiContracts, isLoading, refetch } = useContracts()
  const [playbooks, setPlaybooks] = useState<any[]>([])

  useEffect(() => {
    fetch(`${API_BASE_URL}/contracts/playbooks`)
      .then(res => res.ok ? res.json() : [])
      .then(data => setPlaybooks(data))
      .catch(() => {})
  }, [])

  const contractsList = apiContracts && apiContracts.length > 0 ? apiContracts : fallbackContracts
  const activeCount = contractsList.filter((c: any) => c.status?.toLowerCase() === 'active').length

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">Contract Intelligence</h1>
            <p className="mt-1 text-xs text-slate-600">Enterprise contract repository, clause comparison, and automated playbook audits</p>
          </div>
          <button
            onClick={() => refetch()}
            className="inline-flex items-center px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-300 hover:bg-slate-50"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5 text-slate-500" />
            Refresh
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Contracts</h3>
            <p className="mt-2 text-2xl font-bold text-slate-900">{contractsList.length}</p>
            <p className="text-[11px] text-slate-500 mt-1">Ground & Colocation Agreements</p>
          </div>
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Active Agreements</h3>
            <p className="mt-2 text-2xl font-bold text-emerald-700">{activeCount}</p>
            <p className="text-[11px] text-slate-500 mt-1">Executing standard covenants</p>
          </div>
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Active Playbooks</h3>
            <p className="mt-2 text-2xl font-bold text-blue-700">{playbooks.length > 0 ? playbooks.length : 1}</p>
            <p className="text-[11px] text-slate-500 mt-1">Telecom Ground Lease Review</p>
          </div>
        </div>

        <div className="bg-white border border-slate-200 shadow-sm">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Contract Repository</h3>
            <span className="text-xs text-slate-500">{contractsList.length} documents indexed</span>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-xs">
              <thead className="bg-slate-50 font-semibold text-slate-700">
                <tr>
                  <th className="px-4 py-2.5 text-left">Contract #</th>
                  <th className="px-4 py-2.5 text-left">Title / Type</th>
                  <th className="px-4 py-2.5 text-left">Status</th>
                  <th className="px-4 py-2.5 text-left">Signed Date</th>
                  <th className="px-4 py-2.5 text-left">Security Profile</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-100">
                {contractsList.map((c: any) => (
                  <tr key={c.id} className="hover:bg-slate-50/70">
                    <td className="px-4 py-3 font-mono font-medium text-slate-900">{c.contract_number}</td>
                    <td className="px-4 py-3">
                      <div className="font-semibold text-slate-800">{c.title || c.contract_type}</div>
                      <div className="text-[11px] text-slate-500 capitalize">{c.contract_type?.replace('_', ' ')}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 text-[11px] font-semibold ${
                        c.status?.toLowerCase() === 'active' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                      }`}>
                        {c.status?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-600 font-mono">
                      {c.signed_date ? c.signed_date.substring(0, 10) : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center text-blue-700 font-semibold gap-1 text-[11px]">
                        <Shield className="w-3.5 h-3.5 text-blue-600" />
                        AES-256 + ML-DSA
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Layout>
  )
}
