export type HeaderCheck = {
  name: string;
  present: boolean;
  value?: string | null;
  recommendation: string;
};

export type PortCheck = {
  port: number;
  service: string;
  open: boolean;
};

export type ScanSummary = {
  target: string;
  normalized_url: string;
  score: number;
  risk_level: string;
  https_enabled: boolean;
  redirects_to_https: boolean;
  server_header?: string | null;
  powered_by_header?: string | null;
  headers: HeaderCheck[];
  ports: PortCheck[];
  recommendations: string[];
};
