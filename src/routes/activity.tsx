import { createFileRoute } from "@tanstack/react-router";
import { ActivityPage } from "@/components/radar/pages";
import { useWorkspace } from "@/components/radar/workspace";

export const Route = createFileRoute("/activity")({
  head: () => ({
    meta: [
      { title: "Login activity — Login Pattern Radar" },
      { name: "description", content: "Search and filter login events and see the signals behind each score." },
      { property: "og:title", content: "Login activity — Login Pattern Radar" },
      { property: "og:description", content: "Search and filter login events and see the signals behind each score." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ActivityRoute,
});

function ActivityRoute() {
  const ws = useWorkspace();
  if (!ws.result) return null;
  return (
    <ActivityPage
      events={ws.events} result={ws.result} search={ws.search} setSearch={ws.setSearch}
      statusFilter={ws.statusFilter} setStatusFilter={ws.setStatusFilter} selectedId={ws.selectedId}
      setSelectedId={ws.setSelectedId} selectedRow={ws.selectedRow}
    />
  );
}
