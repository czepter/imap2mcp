import { lookup } from "dns/promises";
import { isIP } from "net";
import { config } from "../config.js";

export class HostNotAllowedError extends Error {
  readonly code = "HOST_NOT_ALLOWED" as const;
}

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
}

const V4_BLOCKS: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

function isPrivateV4(ip: string): boolean {
  const n = v4ToInt(ip);
  return V4_BLOCKS.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) >>> 0 === (v4ToInt(base) & mask) >>> 0;
  });
}

/** Expand an IPv6 literal to 8 16-bit groups. */
function v6Groups(ip: string): number[] {
  ip = ip.split("%")[0];
  let tail: number[] = [];
  const m = ip.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    const n = v4ToInt(m[2]);
    tail = [n >>> 16, n & 0xffff];
    ip = m[1] + "0:0";
  }
  const [head, rest] = ip.split("::");
  const h = head ? head.split(":") : [];
  const r = rest !== undefined && rest !== "" ? rest.split(":") : [];
  const groups = rest === undefined ? h : [...h, ...Array(8 - h.length - r.length).fill("0"), ...r];
  const out = groups.map((g) => parseInt(g || "0", 16));
  if (tail.length) { out[6] = tail[0]; out[7] = tail[1]; }
  return out;
}

function isPrivateV6(ip: string): boolean {
  const g = v6Groups(ip);
  if (g.slice(0, 7).every((x) => x === 0) && g[7] <= 1) return true; // :: and ::1
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return isPrivateV4(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`); // v4-mapped
  if (g[0] === 0x64 && g[1] === 0xff9b) return isPrivateV4(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`); // NAT64
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  return false;
}

export function isPrivateAddress(ip: string): boolean {
  const k = isIP(ip);
  if (k === 4) return isPrivateV4(ip);
  if (k === 6) return isPrivateV6(ip);
  return true;
}

export function isHostExplicitlyAllowed(host: string): boolean {
  return config.allowPrivateHosts.includes(host.trim().toLowerCase());
}

/**
 * Resolve `host` and reject if any address is private/loopback/link-local, unless the host
 * is listed in ALLOW_PRIVATE_HOSTS. Returns the resolved addresses (callers may connect to
 * these directly, passing the hostname as TLS servername, to avoid DNS rebinding).
 */
export async function assertHostAllowed(host: string): Promise<string[]> {
  const h = host.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!h || h.length > 253 || /[\s/@]/.test(h)) throw new HostNotAllowedError("Invalid host");
  const allowed = isHostExplicitlyAllowed(h);
  let addrs: string[];
  if (isIP(h)) {
    addrs = [h];
  } else {
    try {
      addrs = (await lookup(h, { all: true })).map((a) => a.address);
    } catch {
      throw new HostNotAllowedError("Host could not be resolved");
    }
  }
  if (addrs.length === 0) throw new HostNotAllowedError("Host could not be resolved");
  if (!allowed) {
    for (const a of addrs) {
      if (isPrivateAddress(a)) {
        throw new HostNotAllowedError("Host resolves to a private, loopback or link-local address; add it to ALLOW_PRIVATE_HOSTS to permit");
      }
    }
  }
  return addrs;
}
