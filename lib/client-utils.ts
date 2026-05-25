export function getCsrfToken(): string {
  if (typeof document === "undefined") return "";
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrf-token="));
  return match ? decodeURIComponent(match.split("=")[1]) : "";
}
