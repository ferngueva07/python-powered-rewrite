import { createFileRoute } from "@tanstack/react-router";
import { TestPage } from "@/components/radar/pages";
import { useWorkspace } from "@/components/radar/workspace";

export const Route = createFileRoute("/test")({
  head: () => ({
    meta: [
      { title: "Test a login — Login Pattern Radar" },
      { name: "description", content: "Score a hypothetical sign-in against one person’s history without changing your data." },
      { property: "og:title", content: "Test a login — Login Pattern Radar" },
      { property: "og:description", content: "Score a hypothetical sign-in against one person’s history without changing your data." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: TestRoute,
});

function TestRoute() {
  const { engine, events, result, params } = useWorkspace();
  return result ? <TestPage engine={engine} events={events} result={result} params={params} /> : null;
}
