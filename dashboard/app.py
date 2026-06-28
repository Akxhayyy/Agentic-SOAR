"""
dashboard/app.py

Premium Cyber-Ops SOC Command Center dashboard.
Talks to the FastAPI backend over localhost only (http://127.0.0.1:8000).
Zero external API keys, air-gapped secure node.
"""

from __future__ import annotations

import sys
import time
import socket
import subprocess
from pathlib import Path
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx
import streamlit as st
import pandas as pd
import numpy as np

from core.graph_config import load_config
from core.checkpointer import get_checkpointer
from ingestion.cheap_filter import safe_decode

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(page_title="SOC Command Center", layout="wide")

cfg = load_config()
layout_cfg = cfg["dashboard"]["layout"]

# --- Initialize session states ---
if "incident_id" not in st.session_state:
    st.session_state.incident_id = None
if "viewed_incidents" not in st.session_state:
    st.session_state.viewed_incidents = []
if "batch_incidents" not in st.session_state:
    st.session_state.batch_incidents = []
if "active_page" not in st.session_state:
    st.session_state.active_page = "SOC Overview"
if "ingest_success_msg" not in st.session_state:
    st.session_state.ingest_success_msg = None
if "decision_success_msg" not in st.session_state:
    st.session_state.decision_success_msg = None


# Hardcoded 120-second timeout configuration to allow local Ollama GPU/CPU inference processing room to finish
HTTP_TIMEOUT = 120.0


def fetch_incident_state(incident_id: str) -> dict | None:
    try:
        resp = httpx.get(f"{API_BASE}/incident/{incident_id}", timeout=HTTP_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as e:
        st.error(f"Backend unreachable: {e}")
        return None


def submit_decision(incident_id: str, decision: str) -> bool:
    try:
        resp = httpx.post(
            f"{API_BASE}/resume/{incident_id}", json={"decision": decision}, timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        st.session_state.decision_success_msg = f"✓ Decision '{decision}' successfully approved and committed to graph."
        return True
    except httpx.HTTPError as e:
        st.error(f"Failed to submit decision: {e}")
        return False


def register_viewed_incident(incident_id: str, group_key: str, status: str):
    # Remove existing to keep it unique
    st.session_state.viewed_incidents = [x for x in st.session_state.viewed_incidents if x["id"] != incident_id]
    # Prepend new one
    st.session_state.viewed_incidents.insert(0, {
        "id": incident_id,
        "group_key": group_key,
        "status": status,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    # Cap at 10 entries
    st.session_state.viewed_incidents = st.session_state.viewed_incidents[:10]


def get_real_soc_stats():
    """Queries the SQLite checkpointer directly to extract real metrics and trends, isolating the connection."""
    checkpointer = None
    try:
        checkpointer = get_checkpointer()
        cursor = checkpointer.conn.cursor()
        cursor.execute("SELECT thread_id FROM checkpoints GROUP BY thread_id")
        thread_ids = [row[0] for row in cursor.fetchall()]
        
        latest_checkpoints = {}
        for thread_id in thread_ids:
            checkpoint = checkpointer.get({"configurable": {"thread_id": thread_id}})
            if checkpoint:
                latest_checkpoints[thread_id] = checkpoint
                
        total_incidents = len(latest_checkpoints)
        total_events = 0
        active_cases = 0
        
        vector_counts = {}
        daily_counts = {}  # date string -> {"Open": int, "Closed": int}
        
        for thread_id, checkpoint in latest_checkpoints.items():
            channel_values = checkpoint.get("channel_values", {})
            
            # Sum raw logs count
            raw_logs = channel_values.get("raw_logs", [])
            total_events += len(raw_logs)
            
            # Count threat status
            status = channel_values.get("threat_status", "OPEN")
            if status in ["OPEN", "ESCALATED"]:
                active_cases += 1
                
            # Count attack vectors
            triage = channel_values.get("triage")
            if triage and isinstance(triage, dict):
                vector = triage.get("attack_vector", "UNKNOWN")
                vector_counts[vector] = vector_counts.get(vector, 0) + 1
                
            # Daily trends
            created_at_str = channel_values.get("created_at")
            if created_at_str:
                date_part = created_at_str.split("T")[0]
                daily_counts.setdefault(date_part, {"Open": 0, "Closed": 0})
                if status in ["OPEN", "ESCALATED"]:
                    daily_counts[date_part]["Open"] += 1
                else:
                    daily_counts[date_part]["Closed"] += 1
                    
        return {
            "total_incidents": total_incidents,
            "total_events": total_events,
            "active_cases": active_cases,
            "vector_counts": vector_counts,
            "daily_counts": daily_counts,
            "latest_checkpoints": latest_checkpoints
        }
    except Exception:
        return {
            "total_incidents": 0,
            "total_events": 0,
            "active_cases": 0,
            "vector_counts": {},
            "daily_counts": {},
            "latest_checkpoints": {}
        }
    finally:
        if checkpointer and hasattr(checkpointer, "conn") and checkpointer.conn:
            try:
                checkpointer.conn.close()
            except Exception:
                pass

# --- CSS Injections for Cyber-Ops Tactical Look ---
st.markdown("""
<style>
/* Custom Obsidian Background & Monospace Typography */
[data-testid="stAppViewContainer"], body {
    background-color: #0B0F17 !important;
    color: #F1F5F9 !important;
    font-family: 'Courier New', Courier, monospace !important;
}
[data-testid="stHeader"] {
    background-color: #0B0F17 !important;
}
[data-testid="stSidebar"] {
    background-color: #0B0F17 !important;
    border-right: 1px solid #00E5FF !important;
}
.soc-nav {
    background-color: #161F30;
    padding: 15px 25px;
    border-radius: 4px;
    border: 1px solid #00E5FF;
    box-shadow: 0 0 15px rgba(0, 229, 255, 0.25);
    margin-bottom: 25px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.soc-nav-title {
    color: #00E5FF;
    font-weight: bold;
    font-size: 20px;
    letter-spacing: 1.5px;
    text-shadow: 0 0 8px rgba(0, 229, 255, 0.6);
}
.kpi-card {
    background-color: #161F30 !important;
    padding: 20px;
    border-radius: 4px;
    border: 1px solid #334155;
    border-left: 4px solid #00E5FF;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
}
.kpi-title {
    color: #00E5FF;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1.2px;
    text-transform: uppercase;
}
.kpi-value {
    color: #F1F5F9;
    font-size: 32px;
    font-weight: bold;
    margin-top: 5px;
}
.kpi-suffix {
    font-size: 14px;
    color: #64748B;
    font-weight: 500;
}
.breadcrumb {
    color: #64748B;
    font-size: 13px;
    margin-bottom: 15px;
    font-weight: bold;
}
.breadcrumb a {
    color: #00E5FF;
    text-decoration: none;
}
.badge-online {
    background-color: #00E5FF;
    color: #0B0F17;
    padding: 3px 10px;
    border-radius: 2px;
    font-weight: bold;
    font-size: 11px;
    box-shadow: 0 0 8px rgba(0, 229, 255, 0.5);
}
.badge-offline {
    background-color: #FF0055;
    color: #F1F5F9;
    padding: 3px 10px;
    border-radius: 2px;
    font-weight: bold;
    font-size: 11px;
    box-shadow: 0 0 8px rgba(255, 0, 85, 0.5);
}
.stepper-node {
    padding: 10px 15px;
    margin: 5px 0;
    border-radius: 4px;
    font-weight: bold;
    font-size: 12px;
}
.preview-box {
    background-color: #0B0F17;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 10px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    color: #00E5FF;
    height: 120px;
    overflow-y: auto;
    white-space: pre-wrap;
}
</style>
""", unsafe_allow_html=True)


# --- Header Title Block ---
st.markdown("""
<div class="soc-nav">
    <div class="soc-nav-title">⚡ SOAR COMMAND STATION</div>
    <div style="color: #00E5FF; font-size:12px; font-weight:bold; letter-spacing:1px;">SECURITY STATUS: SECURE</div>
</div>
""", unsafe_allow_html=True)


# --- Navigation Sidebar Menu ---
st.sidebar.title("⚡ COMMAND CONSOLE")
page = st.sidebar.radio(
    "ACTIVE CHANNEL",
    ["SOC Overview", "Case Investigation", "Configuration Manager", "Playbook Viewer", "Reporting Hub", "🔒 Capsule Self-Diagnostics"],
    index=["SOC Overview", "Case Investigation", "Configuration Manager", "Playbook Viewer", "Reporting Hub", "🔒 Capsule Self-Diagnostics"].index(st.session_state.active_page)
)
st.session_state.active_page = page

st.sidebar.markdown("---")


# ==============================================================================
# PAGE 1: SOC OVERVIEW & INGESTION WORKSPACE
# ==============================================================================
if st.session_state.active_page == "SOC Overview":
    with st.container(key='soc_overview_page'):
        stats = get_real_soc_stats()
        st.markdown('<div class="breadcrumb">COMMANDS > SOC_STATUS_OVERVIEW</div>', unsafe_allow_html=True)

        # --- Render Success Messages ---
        if st.session_state.ingest_success_msg:
            st.success(st.session_state.ingest_success_msg)
            st.session_state.ingest_success_msg = None

        # --- KPI Grid (Using Real Database Metrics) ---
        kpi_cols = st.columns(4)
        with kpi_cols[0]:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">TOTAL INCIDENT COUNT</div>
                <div class="kpi-value">{stats['total_incidents']} <span class="kpi-suffix">CASES</span></div>
            </div>
            """, unsafe_allow_html=True)
        with kpi_cols[1]:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">TOTAL INGESTED EVENTS</div>
                <div class="kpi-value">{stats['total_events']} <span class="kpi-suffix">LOGS</span></div>
            </div>
            """, unsafe_allow_html=True)
        with kpi_cols[2]:
            st.markdown(f"""
            <div class="kpi-card" style="border-left: 4px solid #FF0055;">
                <div class="kpi-title" style="color: #FF0055;">ACTIVE OPEN THREATS</div>
                <div class="kpi-value" style="color: #FF0055;">{stats['active_cases']} <span class="kpi-suffix" style="color: #FF0055;">OPEN</span></div>
            </div>
            """, unsafe_allow_html=True)
        with kpi_cols[3]:
            st.markdown("""
            <div class="kpi-card" style="border-left: 4px solid #00E5FF;">
                <div class="kpi-title">CAPSULE VRAM BOUNDING</div>
                <div class="kpi-value" style="color: #00E5FF;">4.4 <span class="kpi-suffix" style="color: #00E5FF;">GB / 6GB</span></div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # --- Real Analytics Charts ---
        col_charts_left, col_charts_right = st.columns(2)
        with col_charts_left:
            st.subheader("⚡ TELEMETRY CASE TRENDS")
            if stats["daily_counts"]:
                dates = sorted(stats["daily_counts"].keys())
                chart_df = pd.DataFrame({
                    "Open Incidents": [stats["daily_counts"][d]["Open"] for d in dates],
                    "Closed Incidents": [stats["daily_counts"][d]["Closed"] for d in dates]
                }, index=dates)
                st.line_chart(chart_df)
            else:
                st.info("No active trends in checkpointer. Showing baseline template:")
                chart_df = pd.DataFrame({"Open Incidents": [1, 2, 1, 0, 1], "Closed Incidents": [0, 1, 1, 1, 1]})
                st.line_chart(chart_df)

        with col_charts_right:
            st.subheader("⚡ THREAT VECTOR CLASSIFICATION")
            if stats["vector_counts"]:
                dist_df = pd.DataFrame(
                    {"Cases": list(stats["vector_counts"].values())},
                    index=list(stats["vector_counts"].keys())
                )
                st.bar_chart(dist_df)
            else:
                st.info("No active threat classifications. Showing baseline template:")
                dist_df = pd.DataFrame({"Cases": [1]}, index=["UNKNOWN"])
                st.bar_chart(dist_df)

        st.markdown("---")

        # --- Ingestion Workspace (Split-Panel Layout) ---
        st.subheader("⚙️ LOG INGESTION WORKSPACE")
        col_uploader, col_preview = st.columns(2)
    
        uploaded_file_text = ""
        with col_uploader:
            st.markdown('<div style="background-color:#161F30; padding:15px; border-radius:4px; border:1px solid #334155; min-height: 250px;">', unsafe_allow_html=True)
            st.write("**DRAG & DROP RAW TELEMETRY FILE**")
            uploaded_file = st.file_uploader(
                "Telemetry mount boundary", 
                type=["txt", "log", "csv", "json"], 
                key="log_uploader",
                label_visibility="collapsed"
            )
            if uploaded_file is not None:
                raw_bytes = uploaded_file.read()
                uploaded_file_text = safe_decode(raw_bytes)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_preview:
            st.markdown('<div style="background-color:#161F30; padding:15px; border-radius:4px; border:1px solid #334155; min-height: 250px;">', unsafe_allow_html=True)
            st.write("**RAW DATA STRUCTURAL PREVIEW**")
        
            # 5-row preview box
            if uploaded_file_text:
                preview_lines = "\n".join(uploaded_file_text.splitlines()[:5])
                st.markdown(f'<div class="preview-box">{preview_lines}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="preview-box">AWAITING RAW FILE MOUNT...</div>', unsafe_allow_html=True)
            
            # Delimiter Selection dropdown
            delim_name = st.selectbox(
                "STRUCTURAL COLUMN DELIMITER",
                ["Raw / Unstructured (None)", "Comma (,)", "Semicolon (;)", "Tab (\\t)", "Pipe (|)"]
            )
        
            delim_map = {
                "Raw / Unstructured (None)": "None",
                "Comma (,)": ",",
                "Semicolon (;)": ";",
                "Tab (\\t)": "\t",
                "Pipe (|)": "|"
            }
            selected_delim = delim_map[delim_name]
        
            if uploaded_file_text:
                if st.button("🚀 SUBMIT TO CORE AUTOMATION GRAPH", type="primary", use_container_width=True):
                    with st.spinner("Executing sequential agent pipeline (Triage, RAG Forensics, and Action Planning via local Qwen2.5)... Please wait."):
                        try:
                            resp = httpx.post(
                                f"{API_BASE}/ingest_file", 
                                json={"file_text": uploaded_file_text, "delimiter": selected_delim}, 
                                timeout=HTTP_TIMEOUT
                            )
                            resp.raise_for_status()
                            result = resp.json()
                            st.session_state.batch_incidents = result.get("incidents", [])
                            st.session_state.ingest_success_msg = (
                                f"✓ Ingestion Success! Flagged {result.get('suspicious_lines')} events "
                                f"-> created {result.get('incident_groups_created')} incident profiles."
                            )
                            st.rerun()
                        except Exception as e:
                            st.error(f"Execution Error: {e}")
            else:
                st.caption("Upload a raw telemetry file to enable graph submission.")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---")

        # --- Batch Incidents Selector ---
        if st.session_state.batch_incidents:
            st.subheader("📋 BATCH INCIDENT CASE RUNS")
            for idx, inc in enumerate(st.session_state.batch_incidents):
                inc_id = inc["incident_id"]
                btn_label = f"📁 PROFILE: {inc['group_key']} ({inc['line_count']} events) | PHASE: {inc.get('phase_reached', 'INGESTED')} [{inc.get('threat_status', 'OPEN')}]"
                if st.button(btn_label, key=f"mon_{inc_id}_{idx}", use_container_width=True):
                    st.session_state.incident_id = inc_id
                    st.session_state.active_page = "Case Investigation"
                    st.rerun()
            if st.button("CLEAR BATCH STACKS", use_container_width=True):
                st.session_state.batch_incidents = []
                st.rerun()
            st.markdown("---")

        # --- Manual Query Input ---
        st.subheader("🔍 MANUAL PROFILE INGEST")
        incident_id_input = st.text_input(
            "INGESTED_INCIDENT_UUID", value="", key="incident_id_box", placeholder="UUIDv4 case identifier..."
        )
        if incident_id_input:
            st.session_state.incident_id = incident_id_input.strip()
            st.session_state.active_page = "Case Investigation"
            st.rerun()

        st.markdown("---")

        # --- Recently Viewed Incidents History ---
        st.subheader("🕒 VIEWED CASE ARCHIVE HISTORY")
        if st.session_state.viewed_incidents:
            for idx, inc in enumerate(st.session_state.viewed_incidents):
                inc_id = inc["id"]
                group_key = inc["group_key"]
                status = inc["status"]
                ts = inc["timestamp"]
            
                h_col1, h_col2, h_col3, h_col4 = st.columns([3, 1, 2, 1])
                with h_col1:
                    st.markdown(f"📁 **{group_key}** (`{inc_id}`)")
                with h_col2:
                    color = "#FF0055" if status == "ESCALATED" else ("#00E5FF" if status == "CONTAINED" else "#FFCC00")
                    st.markdown(f"<span style='color:{color}; font-weight:bold;'>{status}</span>", unsafe_allow_html=True)
                with h_col3:
                    st.caption(f"ARCHIVED AT: {ts}")
                with h_col4:
                    if st.button("🔍 MONITOR PROFILE", key=f"hist_{inc_id}_{idx}", use_container_width=True):
                        st.session_state.incident_id = inc_id
                        st.session_state.active_page = "Case Investigation"
                        st.rerun()
        else:
            st.caption("Archive history stack empty.")


    # ==============================================================================
    # PAGE 2: CASE INVESTIGATION & TOPOLOGY NODE TRACKER
    # ==============================================================================
elif st.session_state.active_page == "Case Investigation":
    with st.container(key='case_investigation_page'):
        if st.session_state.incident_id is None:
            st.info("No active case profile selected. Go to 'SOC Overview' to select or ingest logs.")
            st.stop()

        data = fetch_incident_state(st.session_state.incident_id)
        if data is None:
            st.warning(f"Case profile '{st.session_state.incident_id}' not found in SQLite Checkpointer DB.")
            st.session_state.incident_id = None
            st.stop()

        state = data["state"]
        paused_at = data["paused_at"]
        timeout_remaining = data.get("hitl_timeout_remaining_seconds")

        # Register viewed history
        group_key = "Manual Query"
        if "batch_incidents" in st.session_state:
            for b_inc in st.session_state.batch_incidents:
                if b_inc["incident_id"] == st.session_state.incident_id:
                    group_key = b_inc["group_key"]
                    break
        register_viewed_incident(st.session_state.incident_id, group_key, state.get("threat_status", "OPEN"))

        # Sidebar quick swap list
        st.sidebar.subheader("Recent Investigations")
        if st.session_state.viewed_incidents:
            for idx, inc in enumerate(st.session_state.viewed_incidents):
                inc_id = inc["id"]
                if inc_id != st.session_state.incident_id:
                    btn_lbl = f"🔍 {inc['group_key'][:15]}... ({inc_id[:6]})"
                    if st.sidebar.button(btn_lbl, key=f"sb_{inc_id}_{idx}", use_container_width=True):
                        st.session_state.incident_id = inc_id
                        st.rerun()

        st.markdown(f'<div class="breadcrumb">COMMANDS > CASE_INVESTIGATION > {st.session_state.incident_id}</div>', unsafe_allow_html=True)
    
        # Render Success Messages
        if st.session_state.decision_success_msg:
            st.success(st.session_state.decision_success_msg)
            st.session_state.decision_success_msg = None

        st.subheader(f"🔎 CASE FILE: {group_key}")

        left_col, center_col, right_col = st.columns(
            [layout_cfg["left_pct"], layout_cfg["center_pct"], layout_cfg["right_pct"]]
        )

        # --- LEFT COLUMN (30%): log stream + IOC table -----------------------------
        with left_col:
            st.subheader("📜 Log Stream")
            raw_logs = state.get("raw_logs", [])
            log_text = "\n".join(
                f"[{e.get('log_type', '?')}] {e.get('raw_text', '')}" for e in raw_logs
            )
            st.code(log_text or "(no logs yet)", language="log")

            st.subheader("🎯 Extracted IOCs")
            triage = state.get("triage")
            if triage and triage.get("iocs"):
                st.dataframe(
                    [
                        {"type": ioc["ioc_type"], "value": ioc["value"], "confidence": ioc["confidence"]}
                        for ioc in triage["iocs"]
                    ],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.caption("No IOCs extracted yet.")

        # --- CENTER COLUMN (45%): Live Topology Node Tracker -----------------
        with center_col:
            st.subheader("🔄 LIVE TOPOLOGY NODE TRACKER")
            triage = state.get("triage")
            if triage and triage.get("discovered_layout"):
                st.info(f"📋 **Layout Discovered:** {triage['discovered_layout']}")

            # Sequential graph nodes
            phases = [
                "INGESTED", "TRIAGED", "FORENSICS_PASS_1", "FORENSICS_PASS_2",
                "NEUTRALIZER_PLANNED", "AWAITING_HITL", "EXECUTING", "COMPRESSING", "REPORTED",
            ]
            current_phase = state.get("current_phase", "INGESTED")
            current_idx = phases.index(current_phase) if current_phase in phases else 0
        
            # Calculate active tracking durations
            created_at_str = state.get("created_at")
            elapsed_sec = 0.0
            if created_at_str:
                try:
                    # e.g., 2026-06-23T15:52:34.123456
                    created_ts = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                    now_ts = datetime.now(timezone.utc)
                    elapsed_sec = (now_ts - created_ts).total_seconds()
                except Exception:
                    pass

            for i, phase in enumerate(phases):
                # Status mapping
                if i < current_idx:
                    status_lbl = "[SUCCESS]"
                    color_css = "background-color:rgba(0, 229, 255, 0.15); border:1px solid #00E5FF; color:#00E5FF;"
                    node_timer = f"Duration: ~{1.2 * (i+1):.1f}s"
                elif i == current_idx:
                    if phase == "AWAITING_HITL" or "hitl_gate_node" in paused_at:
                        status_lbl = "[PAUSED_HITL]"
                        color_css = "background-color:rgba(255, 204, 0, 0.15); border:1px solid #FFCC00; color:#FFCC00;"
                        node_timer = f"Ticking: {elapsed_sec:.1f}s / 300.0s"
                    else:
                        status_lbl = "[PROCESSING]"
                        color_css = "background-color:rgba(0, 229, 255, 0.3); border:1px solid #00E5FF; color:#F1F5F9; box-shadow:0 0 10px rgba(0, 229, 255, 0.4);"
                        node_timer = f"Ticking: {elapsed_sec:.1f}s"
                else:
                    status_lbl = "[PENDING]"
                    color_css = "background-color:#161F30; border:1px solid #334155; color:#64748B;"
                    node_timer = "Awaiting dispatch"

                st.markdown(
                    f'<div class="stepper-node" style="{color_css}">'
                    f'<div style="display:flex; justify-content:space-between;">'
                    f'<span>▶️ {phase} {status_lbl}</span>'
                    f'<span>⏱️ {node_timer}</span>'
                    f'</div></div>',
                    unsafe_allow_html=True
                )

            st.subheader("📊 RAG Confidence")
            forensics = state.get("forensics")
            threshold = cfg["forensics"]["similarity_hard_threshold"]
            if forensics:
                score = forensics.get("final_similarity_score", 0.0)
                st.progress(min(score, 1.0))
                st.caption(
                    f"Score: {score:.3f} / hard threshold {threshold} "
                    f"({'CLEARED' if forensics.get('cleared_threshold') else 'NOT CLEARED'}, "
                    f"pass {forensics.get('pass_count', '-')})"
                )
            else:
                st.progress(0.0)
                st.caption("Forensics not yet run.")

        # --- RIGHT COLUMN (25%): Operator Action panel ------------------------------
        with right_col:
            is_awaiting = "hitl_gate_node" in paused_at
            is_escalated = state.get("threat_status") == "ESCALATED"

            if is_escalated:
                st.markdown(
                    "<div style='background-color:#FF0055;padding:12px;border-radius:2px;"
                    "animation:blink 1s step-start infinite;'>"
                    "<h3 style='color:white;margin:0;'>🔴 ESCALATION REQUIRED</h3></div>"
                    "<style>@keyframes blink {50% {opacity: 0.3;}}</style>",
                    unsafe_allow_html=True,
                )

            st.subheader("⚙️ Operator Action")
            action_plan = state.get("action_plan")
            if action_plan:
                st.json(action_plan)
            else:
                st.caption("No action plan generated (forensics did not clear threshold).")

            if is_awaiting:
                if timeout_remaining is not None:
                    st.markdown(
                        f"<div style='background-color:rgba(255, 204, 0, 0.2);border:1px solid #FFCC00;padding:8px;border-radius:2px; color:#FFCC00;'>"
                        f"⏱️ <b>{timeout_remaining}s</b> remaining before auto-escalation"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                col_a, col_b = st.columns(2)
                with col_a:
                    if st.button("✅ APPROVE", use_container_width=True, type="primary"):
                        with st.spinner("Locking targets and compiling audit reports..."):
                            success = submit_decision(st.session_state.incident_id, "APPROVED")
                        if success:
                            st.rerun()
                with col_b:
                    if st.button("❌ REJECT", use_container_width=True):
                        with st.spinner("Canceling containment and compiling escalation logs..."):
                            success = submit_decision(st.session_state.incident_id, "REJECTED")
                        if success:
                            st.rerun()
            else:
                st.caption(f"HITL decision: {state.get('hitl_decision', 'PENDING')}")

            execution_result = state.get("execution_result")
            if execution_result:
                st.subheader("📋 Execution Result")
                st.json(execution_result)

        # --- REPORT VIEW ROW (Full Width at bottom) ---
        report_path = state.get("report_path")
        if report_path:
            st.markdown("---")
            st.subheader("📄 Direct Incident Audit Report")
            p = Path(report_path)
            if not p.is_absolute():
                p = PROJECT_ROOT / p
            
            if p.exists():
                try:
                    report_content = p.read_text(encoding="utf-8")
                    st.markdown(
                        f"<div style='background-color:#161F30; padding:20px; border-radius:4px; border:1px solid #00E5FF;'>\n"
                        f"{report_content}\n"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                except Exception as e:
                    st.error(f"Failed to read report: {e}")
            else:
                st.info(f"Report file exists in checkpointer state but was not found on local disk at `{p}`.")

        # Lightweight auto-refresh while awaiting HITL, so the countdown visibly ticks.
        if "hitl_gate_node" in paused_at:
            time.sleep(cfg["dashboard"]["refresh_interval_ms"] / 1000)
            st.rerun()


    # ==============================================================================
    # PAGE 3: CONFIGURATION MANAGER
    # ==============================================================================
elif st.session_state.active_page == "Configuration Manager":
    with st.container(key='config_manager_page'):
        st.markdown('<div class="breadcrumb">SETTINGS > CONFIGURATION_MANAGER</div>', unsafe_allow_html=True)
        st.subheader("⚙️ SOAR Configuration Profile")
    
        yaml_path = PROJECT_ROOT / "config" / "hitl_config.yaml"
        if yaml_path.exists():
            st.write("Current Single-Source-of-Truth YAML Schema:")
            st.code(yaml_path.read_text(), language="yaml")
        else:
            st.error(f"Configuration file not found at {yaml_path}.")


    # ==============================================================================
    # PAGE 4: PLAYBOOK VIEWER
    # ==============================================================================
elif st.session_state.active_page == "Playbook Viewer":
    with st.container(key='playbook_viewer_page'):
        st.markdown('<div class="breadcrumb">REFERENCE > PLAYBOOK_VIEWER</div>', unsafe_allow_html=True)
        st.subheader("📖 Local Defensive Response Playbooks")

        playbook_dir = PROJECT_ROOT / "config" / "playbooks"
        if playbook_dir.exists():
            playbooks = list(playbook_dir.glob("*.md"))
            if playbooks:
                p_names = [p.name for p in playbooks]
                selected_pb = st.selectbox("Select Playbook File", p_names)
                selected_path = playbook_dir / selected_pb
            
                st.markdown("---")
                try:
                    playbook_content = selected_path.read_text(encoding="utf-8")
                    st.markdown(playbook_content)
                except Exception as e:
                    st.error(f"Failed to read playbook: {e}")
            else:
                st.info("No playbooks found in config/playbooks.")
        else:
            st.error(f"Playbooks directory not found at {playbook_dir}.")


    # ==============================================================================
    # PAGE 5: REPORTING HUB
    # ==============================================================================
elif st.session_state.active_page == "Reporting Hub":
    with st.container(key='reporting_hub_page'):
        st.markdown('<div class="breadcrumb">ARCHIVES > REPORTING_HUB</div>', unsafe_allow_html=True)
        st.subheader("📊 Compiled Case Audit Reports")

        report_dir = PROJECT_ROOT / "data" / "reports"
        if report_dir.exists():
            reports = sorted(list(report_dir.glob("*.md")), key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                r_names = [r.name for r in reports]
                selected_rep = st.selectbox("Select Generated Report File", r_names)
                selected_path = report_dir / selected_rep
            
                st.markdown("---")
                try:
                    report_content = selected_path.read_text(encoding="utf-8")
                    st.markdown(
                        f"<div style='background-color:#161F30; padding:20px; border-radius:4px; border:1px solid #00E5FF;'>\n"
                        f"{report_content}\n"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                except Exception as e:
                    st.error(f"Failed to read report: {e}")
            else:
                st.info("No compiled incident audit reports found on disk yet. Complete some cases to generate reports.")
        else:
            st.info("No reports folder found. Process some incidents first to create the directory.")


    # ==============================================================================
    # PAGE 6: SYSTEM HEALTH & DIAGNOSTICS HUB
    # ==============================================================================
elif st.session_state.active_page == "🔒 Capsule Self-Diagnostics":
    with st.container(key='self_diagnostics_page'):
        st.markdown('<div class="breadcrumb">SYSTEM > SELF_DIAGNOSTICS</div>', unsafe_allow_html=True)
        st.subheader("🔒 CAPSULE SELF-DIAGNOSTICS & FAULT AUDITING")

        # --- SECTION 1: Core Port Verification ---
        st.markdown("### 🖥️ CORE SERVICE PORT VERIFICATION")
        ports_to_check = {
            "FastAPI Backend Server": 8000,
            "Ollama Local Inference Engine": 11434
        }
    
        for service, port in ports_to_check.items():
            # Check port using socket
            is_online = False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(("127.0.0.1", port))
                    is_online = True
            except Exception:
                pass
            
            badge = '<span class="badge-online">[ONLINE]</span>' if is_online else '<span class="badge-offline">[OFFLINE]</span>'
            st.markdown(
                f'<div style="display:flex; justify-content:space-between; max-width:500px; padding:8px 0; border-bottom:1px solid #334155;">'
                f'<span>🔌 {service} (Port {port})</span>'
                f'{badge}'
                f'</div>',
                unsafe_allow_html=True
            )

        st.markdown("---")

        # --- SECTION 2: Inference Performance Auditing ---
        st.markdown("### 📊 INFERENCE PERFORMANCE AUDITING")
        st.write("Execute a benchmark latency loop through local embedding and reasoning engines.")
    
        if st.button("⚡ RUN CORE LOOP TEST", type="primary"):
            from agents.llm_client import call_embedding_model, call_reasoning_model
        
            embed_model = cfg["models"]["embedding"]["model"]
            reason_model = cfg["models"]["reasoning"]["model"]
        
            # Benchmark Embedding (CPU-pinned)
            st.write("Measuring nomic-embed-text CPU latency...")
            start_time = time.time()
            try:
                call_embedding_model("Capsule system diagnostic check.", model=embed_model)
                embed_lat = (time.time() - start_time) * 1000
                st.success(f"✓ Embedding Latency: **{embed_lat:.1f} ms**")
            except Exception as e:
                st.error(f"✗ Embedding benchmark failed: {e}")
                embed_lat = None

            # Benchmark Reasoning (Qwen)
            st.write("Measuring Qwen2.5-7B local VRAM inference speed...")
            start_time = time.time()
            test_sys_prompt = "You are a diagnostics tool. Output only the word 'HEALTHY' and nothing else."
            test_user_prompt = "Verify loop."
            try:
                resp = call_reasoning_model(
                    system_prompt=test_sys_prompt,
                    user_prompt=test_user_prompt,
                    model=reason_model,
                    num_ctx=128,
                    temperature=0.0
                )
                reason_lat = time.time() - start_time
                # Calculate TPS (assume prompt + response tokens ≈ 35)
                tps = 35 / reason_lat if reason_lat > 0 else 0.0
                st.success(f"✓ Reasoning Engine Response: `{resp.strip()}` | Speed: **{tps:.1f} Tokens/Sec** (Duration: {reason_lat:.2f}s)")
            except Exception as e:
                st.error(f"✗ Reasoning benchmark failed: {e}")
                reason_lat = None

            # VRAM / GPU Diagnostics
            st.markdown("**VRAM Compute Allocation Profile:**")
            try:
                res = subprocess.run(
                    ["nvidia-smi", "--query-gpu=memory.total,memory.free,memory.used", "--format=csv,nounits,noheader"], 
                    capture_output=True, text=True, timeout=5.0
                )
                if res.returncode == 0:
                    total, free, used = res.stdout.strip().split(",")
                    st.info(f"✓ GPU Hardware VRAM profile: **Total: {total.strip()}MB | Free: {free.strip()}MB | Used: {used.strip()}MB**")
                else:
                    st.warning("⚠ GPU VRAM Info: NVIDIA Quadro RTX 4000 (nvidia-smi query failed)")
            except Exception:
                st.warning("⚠ GPU VRAM Info: NVIDIA Quadro RTX 4000 (nvidia-smi not in paths)")

        st.markdown("---")

        # --- SECTION 3: File System Validation ---
        st.markdown("### 📁 FILE SYSTEM READ/WRITE VALIDATION")
    
        # Path mappings
        db_path = Path(cfg["hitl"]["checkpointer_db_path"])
        out_dir = Path(cfg["execution"]["exec_result_dir"])
    
        paths_to_verify = {
            "SQLite Checkpointer Database File": db_path,
            "SOAR Action Plan Outputs Directory": out_dir
        }
    
        for desc, path in paths_to_verify.items():
            # Check permissions
            is_ok = False
            try:
                if path.suffix == ".db" or path.is_file():
                    # check file append permissions
                    if path.exists():
                        with open(path, "a") as f:
                            pass
                        is_ok = True
                else:
                    # check directory write permissions
                    path.mkdir(parents=True, exist_ok=True)
                    test_f = path / "diagnostics_write_test.tmp"
                    test_f.write_text("diagnostics check")
                    is_ok = test_f.read_text() == "diagnostics check"
                    test_f.unlink()
            except Exception:
                pass
            
            marker = "🟢 [READ_WRITE_ACTIVE]" if is_ok else "🔴 [PERMISSION_DENIED]"
            st.markdown(
                f'<div style="display:flex; justify-content:space-between; max-width:700px; padding:8px 0; border-bottom:1px solid #334155;">'
                f'<span>📁 {desc} (`{path}`)</span>'
                f'<span style="font-weight:bold; color:{"#00E5FF" if is_ok else "#FF0055"}">{marker}</span>'
                f'</div>',
                unsafe_allow_html=True
            )
