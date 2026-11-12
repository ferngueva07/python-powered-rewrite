import { createFileRoute } from "@tanstack/react-router";
import { ScanFilesPage } from "@/components/radar/scan-files";
import { useWorkspace } from "@/components/radar/workspace";

export const Route = createFileRoute("/scan")({
  head: () => ({
    meta: [
      { title: "Scan files — Login Pattern Radar" },
      { name: "description", content: "Inspect security logs and files for suspicious patterns, secrets, and risky file types locally." },
      { property: "og:title", content: "Scan files — Login Pattern Radar" },
      { property: "og:description", content: "Inspect security logs and files for suspicious patterns, secrets, and risky file types locally." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ScanRoute,
});

function ScanRoute() {
  const { params, scan, setScan, loadScannedEvents } = useWorkspace();
  return <ScanFilesPage params={params} scan={scan} setScan={setScan} onLoadEvents={loadScannedEvents} />;
}
