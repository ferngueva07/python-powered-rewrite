import { createFileRoute } from "@tanstack/react-router";
import { Overview } from "@/components/radar/pages";
import { useWorkspace } from "@/components/radar/workspace";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Login Pattern Radar — Analysis overview" },
      { name: "description", content: "Summary metrics and recently flagged sign-ins, scored in your browser." },
      { property: "og:title", content: "Login Pattern Radar — Analysis overview" },
      { property: "og:description", content: "Summary metrics and recently flagged sign-ins, scored in your browser." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: OverviewRoute,
});

function OverviewRoute() {
  const { result, params } = useWorkspace();
  return result ? <Overview result={result} params={params} /> : null;
}
