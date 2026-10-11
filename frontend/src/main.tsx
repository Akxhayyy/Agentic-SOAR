import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./index.css";
import Layout from "./components/Layout";
import IncidentsPage from "./pages/Incidents";
import IncidentDetailPage from "./pages/IncidentDetail";
import IngestPage from "./pages/Ingest";
import PlaybooksPage from "./pages/Playbooks";
import EvaluationPage from "./pages/Evaluation";
import SystemPage from "./pages/System";

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5_000, retry: 1, refetchOnWindowFocus: true } },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<IncidentsPage />} />
            <Route path="incidents/:id" element={<IncidentDetailPage />} />
            <Route path="ingest" element={<IngestPage />} />
            <Route path="playbooks" element={<PlaybooksPage />} />
            <Route path="evaluation" element={<EvaluationPage />} />
            <Route path="system" element={<SystemPage />} />
            <Route path="*" element={<IncidentsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
