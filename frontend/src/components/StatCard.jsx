const TONES = {
  blue: "border-sky-200 bg-sky-50 text-sky-700",
  green: "border-emerald-200 bg-emerald-50 text-emerald-700",
  red: "border-rose-200 bg-rose-50 text-rose-700",
  yellow: "border-yellow-200 bg-yellow-50 text-yellow-700",
};

export default function StatCard({ label, value, tone, Icon }) {
  return (
    <div className={`rounded-lg border p-4 ${TONES[tone]}`}>
      <div className="flex items-center justify-between text-sm font-medium"><span>{label}</span><Icon size={18} /></div>
      <div className="mt-2 text-3xl font-semibold">{value}</div>
    </div>
  );
}
