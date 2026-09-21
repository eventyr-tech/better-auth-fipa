/** Parsed hostname only; one terminal DNS root dot is accepted for local names. */
export function isLocalHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (["127.0.0.1", "::1", "[::1]"].includes(host)) return true;
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  if (name.length > 253) return false;
  const labels = name.split(".");
  return (
    labels.at(-1) === "localhost" &&
    labels.every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label),
    )
  );
}
