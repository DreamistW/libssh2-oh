export interface DemoOptions {
  host: string;
  port: number;
  username: string;
  password: string;
  fingerprint: string;
  kex: string;
  legacy: boolean;
}
export interface DemoResult {
  ok: boolean;
  error: string;
  code: number;
  algorithm: string;
  stages: string[];
}
declare const demo: { run(options: DemoOptions): Promise<DemoResult> };
export default demo;
