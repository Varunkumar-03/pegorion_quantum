import { ReactNode, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import {
  Shield,
  Layers,
  Key,
  FileCheck,
  Database,
  Sliders,
  Cpu,
  ExternalLink,
  Lock,
  User,
  CheckCircle2,
  Menu,
  X
} from 'lucide-react'

export interface NavTabItem {
  id: 'inventory' | 'keys' | 'document' | 'vault' | 'policy' | 'benchmarks'
  label: string
  icon: any
}

export const SECURITY_TABS: NavTabItem[] = [
  { id: 'inventory', label: 'Cryptographic Inventory', icon: Layers },
  { id: 'keys', label: 'Key Lifecycle', icon: Key },
  { id: 'document', label: 'Document Envelope & Signatures', icon: FileCheck },
  { id: 'vault', label: 'Evidence Vault & Audit Chain', icon: Database },
  { id: 'policy', label: 'Organization & Legal Hold Policy', icon: Sliders },
  { id: 'benchmarks', label: 'Platform Benchmarks', icon: Cpu },
]

interface LayoutProps {
  children: ReactNode
  activeTab?: 'inventory' | 'keys' | 'document' | 'vault' | 'policy' | 'benchmarks'
  onTabChange?: (tab: 'inventory' | 'keys' | 'document' | 'vault' | 'policy' | 'benchmarks') => void
}

export default function Layout({ children, activeTab = 'inventory', onTabChange }: LayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const router = useRouter()

  const handleSelectTab = (tabId: NavTabItem['id']) => {
    if (onTabChange) {
      onTabChange(tabId)
    } else {
      router.push(`/?tab=${tabId}`)
    }
    setMobileMenuOpen(false)
  }

  return (
    <div className="min-h-screen bg-[#F4F6FA] text-slate-900 flex flex-col">
      {/* Top Header Bar */}
      <header className="bg-[#0B1A2E] border-b border-[#162D4A] sticky top-0 z-50 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Left: Branding */}
            <div className="flex items-center gap-4">
              <Link href="/" className="flex items-center gap-3 focus:outline-none">
                <img
                  src="/vertical-bridge-white.svg"
                  alt="Vertical Bridge"
                  className="h-9 w-auto max-w-[170px] object-contain drop-shadow-sm transition-opacity hover:opacity-90"
                />
                <span className="hidden sm:inline-block border-l border-slate-600 pl-3 text-xs font-semibold tracking-wider uppercase text-slate-300">
                  Quantum PQC Security
                </span>
              </Link>
            </div>

            {/* Right: Operational Status Badges */}
            <div className="hidden md:flex items-center gap-3">
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-950/70 border border-emerald-500/40 text-emerald-300 text-xs font-medium rounded-full">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>NIST FIPS 203/204/205 Active</span>
              </div>

              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 px-3 py-1 text-xs font-medium text-slate-300 hover:text-white bg-[#162D4A] hover:bg-[#1C3A5E] border border-slate-700 transition-colors"
                title="Open Interactive API Docs (Swagger)"
              >
                <span>API Docs</span>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </a>

              <div className="flex items-center gap-2 pl-3 border-l border-slate-700 text-xs text-slate-400">
                <div className="w-7 h-7 rounded-full bg-blue-600/30 border border-blue-500/50 flex items-center justify-center text-blue-300 font-bold">
                  VB
                </div>
                <div className="hidden lg:block text-left">
                  <div className="text-white font-medium text-xs leading-none">Security Officer</div>
                  <div className="text-[10px] text-slate-400 leading-tight">org-vb-default</div>
                </div>
              </div>
            </div>

            {/* Mobile menu button */}
            <div className="flex md:hidden">
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-2 text-slate-300 hover:text-white focus:outline-none"
              >
                {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>

        {/* Primary Navigation Tabs */}
        <div className="bg-[#10243E] border-t border-[#1B3659]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <nav className="hidden md:flex space-x-1 overflow-x-auto py-0">
              {SECURITY_TABS.map((tab) => {
                const Icon = tab.icon
                const isActive = activeTab === tab.id
                return (
                  <button
                    key={tab.id}
                    onClick={() => handleSelectTab(tab.id)}
                    className={`flex items-center gap-2 py-3 px-4 text-xs font-semibold whitespace-nowrap border-b-2 transition-all ${
                      isActive
                        ? 'border-blue-400 text-white bg-[#163356]'
                        : 'border-transparent text-slate-300 hover:text-white hover:bg-[#142B48]'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                    <span>{tab.label}</span>
                  </button>
                )
              })}
            </nav>
          </div>
        </div>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-[#0E2036] border-t border-[#1C385C] px-3 py-2 space-y-1">
            {SECURITY_TABS.map((tab) => {
              const Icon = tab.icon
              const isActive = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => handleSelectTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-medium rounded-none text-left ${
                    isActive
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-slate-300 hover:bg-[#163050] hover:text-white'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              )}
            )}
            <div className="pt-2 border-t border-slate-700/60 mt-2 flex justify-between items-center text-xs text-slate-400 px-3 py-1">
              <span>NIST FIPS 203/204/205 Active</span>
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noreferrer"
                className="text-blue-400 hover:underline"
              >
                Swagger API
              </a>
            </div>
          </div>
        )}
      </header>

      {/* Main Full-Width Content Area */}
      <main className="flex-1 max-w-7xl mx-auto w-full py-6 px-4 sm:px-6 lg:px-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-4 px-4 sm:px-6 lg:px-8 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center text-xs text-slate-500 gap-2">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-600" />
            <span>Pegorion Quantum-Resilient Security Platform • NIST FIPS 203 / 204 / 205 Compliance Engine</span>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-slate-400">Environment: Local Dev Provider</span>
            <span className="text-slate-400">•</span>
            <span className="font-mono text-[11px] text-slate-600">PQC-ENV-1.0</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
