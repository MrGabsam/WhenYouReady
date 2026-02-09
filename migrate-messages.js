import fs from "fs";
import path from "path";

const ROOT = process.cwd();
const FILE = path.join(ROOT, "data", "messages.json");

// Safety backup
const backup = path.join(ROOT, "data", `messages.backup.${Date.now()}.json`);

if (!fs.existsSync(FILE)) {
  console.error("messages.json not found at:", FILE);
  process.exit(1);
}

const rows = JSON.parse(fs.readFileSync(FILE, "utf-8"));
fs.writeFileSync(backup, JSON.stringify(rows, null, 2));

const migrated = rows.map((r) => ({
  ...r,

  // new fields expected by the upgraded backend / UI
  addons: r.addons ?? {},
  currency: r.currency ?? "GBP",
  amountLocal: r.amountLocal ?? null,
  amountGBP: r.amountGBP ?? null,

  // unify media fields
  images: Array.isArray(r.images) ? r.images : [],
  audioUrl: r.audioUrl ?? null,

  // keep existing paidAt if present
  paidAt: r.paidAt ?? null,
}));

fs.writeFileSync(FILE, JSON.stringify(migrated, null, 2));

console.log("✅ Migration complete");
console.log("• Updated:", migrated.length, "records");
console.log("• Backup created:", backup);
console.log("• File updated:", FILE);
