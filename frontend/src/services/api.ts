import type { ScanSummary } from '../types';

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

export async function scanTarget(
  targetUrl: string,
  skipPorts: boolean,
): Promise<ScanSummary> {
  const response = await fetch(`${API_URL}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      target_url: targetUrl,
      skip_ports: skipPorts,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => null);
    throw new Error(error?.detail ?? 'Could not scan target');
  }

  return response.json();
}
