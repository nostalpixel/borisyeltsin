export function daysUntil(date: string, today: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
  const time = Date.parse(`${date}T00:00:00Z`);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 10) !== date) return null;
  return Math.round((time - Date.parse(`${today}T00:00:00Z`)) / 86400000);
}

export function dueLevel(days: number | null): "" | "warning" | "danger" {
  if (days === null || days > 7) return "";
  if (days <= 3) return "danger";
  return "warning";
}

export function dueLabel(days: number): string {
  if (days < 0) return `Overdue by ${Math.abs(days)} d`;
  if (days === 0) return "Due today";
  return `Due in ${days} d`;
}
