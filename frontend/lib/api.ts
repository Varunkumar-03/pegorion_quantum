import { useQuery, useMutation, useQueryClient, type UseMutationOptions } from '@tanstack/react-query'

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'

export interface Document {
  id: string
  filename: string
  file_size: number | null
  mime_type: string | null
  storage_path: string
  uploaded_by: string | null
  uploaded_at: string
  status: string
  document_type: string | null
}

export interface SecurityAlgorithm {
  algorithm: string
  fips_standard: string
  category_parameter_set: string
  claimed_bit_security: string
  classical_equivalent?: string
  status: 'PASS' | 'FAIL' | 'NOT CONFIGURED' | 'NOT TESTED' | 'VERIFICATION UNAVAILABLE'
  purpose: string
  is_post_quantum: boolean
}

export interface SecurityKey {
  key_id: string
  algorithm: string
  fips_standard: string
  purpose: string
  state: 'ACTIVE' | 'ROTATED' | 'REVOKED'
  created_at: string
  public_key_bytes_len: number
  rotation_count: number
}

export function useDocuments() {
  return useQuery<Document[], Error>({
    queryKey: ['documents'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/documents`)
      if (!response.ok) {
        throw new Error('Failed to fetch documents')
      }
      return response.json()
    },
  })
}

export function useUploadDocument(
  options?: UseMutationOptions<Document, Error, File>
) {
  const queryClient = useQueryClient()

  return useMutation<Document, Error, File>({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(`${API_BASE_URL}/documents/upload`, {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        throw new Error('Failed to upload document')
      }

      return response.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['documents'] })
    },
    ...options,
  })
}

export function useSecurityAlgorithms() {
  return useQuery<SecurityAlgorithm[], Error>({
    queryKey: ['security-algorithms'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/security/algorithms`)
      if (!response.ok) throw new Error('Failed to fetch security algorithms')
      return response.json()
    },
  })
}

export function useSecurityKeys() {
  return useQuery<SecurityKey[], Error>({
    queryKey: ['security-keys'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/security/keys`)
      if (!response.ok) throw new Error('Failed to fetch security keys')
      return response.json()
    },
  })
}

export function useEvidenceVaultEvents() {
  return useQuery<any[], Error>({
    queryKey: ['evidence-vault-events'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/security/evidence-vault/events`)
      if (!response.ok) throw new Error('Failed to fetch evidence vault events')
      return response.json()
    },
  })
}

export function useSecurityBenchmarks() {
  return useQuery<any[], Error>({
    queryKey: ['security-benchmarks'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/security/benchmarks`)
      if (!response.ok) throw new Error('Failed to fetch benchmarks')
      return response.json()
    },
  })
}
