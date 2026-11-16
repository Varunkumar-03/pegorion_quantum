import Layout from '../../components/Layout'
import { ShieldCheck, Radio, AlertTriangle, FileText, CheckCircle2, RefreshCw } from 'lucide-react'

const complianceItems = [
  {
    code: 'FAA-PART-77',
    agency: 'Federal Aviation Administration',
    title: 'Safe, Efficient Use, and Preservation of the Navigable Airspace',
    status: 'Compliant',
    lastAudit: '2024-05-15',
    scope: 'Towers exceeding 200ft AGL or near runway glidepaths (Dallas, Houston sites)',
    details: 'Obstruction evaluation notice Form 7460-1 on file with FAA OE/AAA.'
  },
  {
    code: 'FCC-PART-17',
    agency: 'Federal Communications Commission',
    title: 'Construction, Marking, and Lighting of Antenna Structures',
    status: 'Compliant',
    lastAudit: '2024-06-01',
    scope: 'Medium-intensity dual strobe obstruction lighting & daily telemetry',
    details: 'Automated monitoring unit reporting 24/7 status directly to Network Operations.'
  },
  {
    code: 'FCC-NEPA',
    agency: 'FCC / Advisory Council on Historic Preservation',
    title: 'National Environmental Policy Act (NEPA) & Section 106 Historical Review',
    status: 'Compliant',
    lastAudit: '2024-04-10',
    scope: 'Colocation compounds and compound expansion clearances',
    details: 'Phase I ESA clearance and tribal consultation records archived.'
  },
  {
    code: 'TIA-222-H',
    agency: 'Telecommunications Industry Association',
    title: 'Structural Standard for Antenna Supporting Structures and Antennas',
    status: 'Under Review',
    lastAudit: '2024-06-12',
    scope: 'Dallas Site Alpha Massive MIMO 64T64R wind load recertification',
    details: 'Structural engineering calculation in progress by lead PE.'
  }
]

export default function RegulatoryPage() {
  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">Regulatory Intelligence</h1>
            <p className="mt-1 text-xs text-slate-600">FCC tower registrations, FAA Part 77 airspace clearances, and NEPA environmental compliance</p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-300 hover:bg-slate-50"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5 text-slate-500" />
            Refresh
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Monitored Regulations</h3>
            <p className="mt-2 text-2xl font-bold text-slate-900">4 Standards</p>
            <p className="text-[11px] text-slate-500 mt-1">FAA, FCC, NEPA, TIA-222-H</p>
          </div>
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Overall Compliance</h3>
            <p className="mt-2 text-2xl font-bold text-emerald-700">92% Audited</p>
            <p className="text-[11px] text-slate-500 mt-1">Zero outstanding FCC citations</p>
          </div>
          <div className="bg-white border border-slate-200 p-5 shadow-sm">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Antenna Structure Registrations</h3>
            <p className="mt-2 text-2xl font-bold text-blue-700">5 Active ASRs</p>
            <p className="text-[11px] text-slate-500 mt-1">ASR #1049281, #1204855, #1305912...</p>
          </div>
        </div>

        <div className="bg-white border border-slate-200 shadow-sm">
          <div className="px-5 py-3.5 border-b border-slate-200">
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Active Regulatory Mandates & Standards</h3>
          </div>
          <div className="divide-y divide-slate-100">
            {complianceItems.map((item) => (
              <div key={item.code} className="p-5 hover:bg-slate-50/70 transition-colors">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-xs bg-slate-100 text-slate-800 px-2 py-0.5 border border-slate-200">
                      {item.code}
                    </span>
                    <h4 className="font-semibold text-sm text-slate-900">{item.title}</h4>
                  </div>
                  <span className={`inline-flex items-center px-2 py-0.5 text-xs font-semibold w-fit ${
                    item.status === 'Compliant' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                  }`}>
                    {item.status === 'Compliant' ? <CheckCircle2 className="w-3.5 h-3.5 mr-1 text-emerald-600" /> : <AlertTriangle className="w-3.5 h-3.5 mr-1 text-amber-600" />}
                    {item.status.toUpperCase()}
                  </span>
                </div>
                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  <div><span className="font-medium text-slate-700">Agency:</span> {item.agency}</div>
                  <div><span className="font-medium text-slate-700">Scope:</span> {item.scope}</div>
                  <div><span className="font-medium text-slate-700">Audit Status:</span> {item.details} (Last audit: {item.lastAudit})</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  )
}
