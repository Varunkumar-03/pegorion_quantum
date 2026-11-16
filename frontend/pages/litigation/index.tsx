import { useState, useEffect } from 'react'
import Layout from '../../components/Layout'
import { Scale, Calendar, AlertCircle, RefreshCw, Shield } from 'lucide-react'
import { useLegalMatters } from '../../lib/api'

const fallbackCases = [
  { id: 'matter-101', matter_number: 'VB-LEGAL-2024-101', title: 'Lease Risk Review & Asymmetrical Cure Defense - Dallas Site Alpha', matter_type: 'Contract Review', status: 'open', priority: 'high', opened_date: '2024-06-15' },
  { id: 'matter-102', matter_number: 'VB-LEGAL-2024-102', title: 'FAA Part 77 Obstruction Evaluation & Strobe Lighting Compliance', matter_type: 'compliance', status: 'open', priority: 'high', opened_date: '2024-05-20' },
  { id: 'matter-103', matter_number: 'VB-LEGAL-2024-103', title: 'Houston Central Landlord Unilateral Default & Escalation Dispute', matter_type: 'litigation', status: 'open', priority: 'critical', opened_date: '2024-06-01' },
]

export default function LitigationPage() {
  const { data: apiMatters, isLoading, refetch } = useLegalMatters()
  const cases = apiMatters && apiMatters.length > 0 ? apiMatters : fallbackCases

  const openCount = cases.filter((c: any) => c.status?.toLowerCase() === 'open').length
  const criticalCount = cases.filter((c: any) => c.priority?.toLowerCase() === 'critical' || c.priority?.toLowerCase() === 'high').length

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">Litigation & Legal Matters</h1>
            <p className="mt-1 text-xs text-slate-600">Case tracking, precedent research, and cell site dispute management</p>
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
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Active Matters</h3>
            <p className="mt-2 text-2xl font-bold text-slate-900">{cases.length}</p>
            <p className="text-[11px] text-slate-500 mt-1">Pending and open dockets</p>
          </div>
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">High / Critical Priority</h3>
            <p className="mt-2 text-2xl font-bold text-red-700">{criticalCount}</p>
            <p className="text-[11px] text-slate-500 mt-1">Requires immediate legal counsel</p>
          </div>
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Open Proceedings</h3>
            <p className="mt-2 text-2xl font-bold text-amber-700">{openCount}</p>
            <p className="text-[11px] text-slate-500 mt-1">Active negotiation / court matters</p>
          </div>
        </div>

        <div className="bg-white border border-slate-200 shadow-sm">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Legal Matter Repository</h3>
            <span className="text-xs text-slate-500">{cases.length} records active</span>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-xs">
              <thead className="bg-slate-50 font-semibold text-slate-700">
                <tr>
                  <th className="px-4 py-2.5 text-left">Matter #</th>
                  <th className="px-4 py-2.5 text-left">Title</th>
                  <th className="px-4 py-2.5 text-left">Type</th>
                  <th className="px-4 py-2.5 text-left">Status</th>
                  <th className="px-4 py-2.5 text-left">Priority</th>
                  <th className="px-4 py-2.5 text-left">Classification</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-slate-100">
                {cases.map((c: any) => (
                  <tr key={c.id} className="hover:bg-slate-50/70">
                    <td className="px-4 py-3 font-mono font-medium text-slate-900">{c.matter_number || c.id}</td>
                    <td className="px-4 py-3 font-semibold text-slate-800">{c.title}</td>
                    <td className="px-4 py-3 text-slate-600 capitalize">{c.matter_type?.replace('_', ' ')}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 text-[11px] font-semibold ${
                        c.status?.toLowerCase() === 'open' ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'
                      }`}>
                        {c.status?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 text-[11px] font-semibold ${
                        c.priority?.toLowerCase() === 'critical' || c.priority?.toLowerCase() === 'high'
                          ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800'
                      }`}>
                        {c.priority?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center text-purple-700 font-semibold gap-1 text-[11px]">
                        <Shield className="w-3.5 h-3.5 text-purple-600" />
                        RESTRICTED_LEGAL
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
