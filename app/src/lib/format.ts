const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export const num = (n: number) => n.toLocaleString("en-US");

export function clock(d: Date, seconds = false): string {
  const h = d.getHours();
  const m = d.getMinutes().toString().padStart(2, "0");
  const s = seconds ? `:${d.getSeconds().toString().padStart(2, "0")}` : "";
  return `${h % 12 === 0 ? 12 : h % 12}:${m}${s} ${h >= 12 ? "pm" : "am"}`;
}

export const weekday = (d: Date) => DAYS[d.getDay()];
export const monthDay = (d: Date) => `${MONTHS[d.getMonth()]} ${d.getDate()}`;

/** "Tue 9:14 pm", or "Nov 3 9:14 pm" when more than a week ago. */
export function when(ms: number, now: number = Date.now()): string {
  const d = new Date(ms);
  return now - ms > 6 * 86_400_000 ? `${monthDay(d)} ${clock(d)}` : `${weekday(d)} ${clock(d)}`;
}

export const bytes = (n: number) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);

/** "2026-11-04" (local day from the analyzer) -> "Wed" or "Nov 4". */
export function dayLabel(iso: string, many: boolean): string {
  const [y, m, d] = iso.split("-").map(Number);
  const date = new Date(y, m - 1, d);
  return many ? monthDay(date) : weekday(date);
}
