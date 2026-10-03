"""Optional web page:   streamlit run app.py"""
from pathlib import Path

import streamlit as st

from analyze import DEFAULT_KB, analyze_log
from rag import KnowledgeBase, attack_id, load_knowledge

SAMPLES = Path(__file__).parent / "sample_logs"

st.set_page_config(page_title="RAG Log Analyzer", page_icon="🔐")
st.title("🔐 RAG Log Analyzer")
st.caption("Counts evidence in SSH logs with plain Python rules, then retrieves what it means and how to respond "
           "from a security knowledge base. Text taken from logs is sanitised before it is shown.")


@st.cache_resource
def get_kb():
    return KnowledgeBase(load_knowledge(DEFAULT_KB))


upload = st.file_uploader("Upload an SSH auth log (for example /var/log/auth.log)", type=["log", "txt"])
sample = None
if upload is None:
    sample = st.selectbox("No log handy? Try a sample", sorted(p.name for p in SAMPLES.glob("*.log")))
use_llm = st.sidebar.checkbox("Write the summary with a local LLM (Ollama)")
model = st.sidebar.text_input("Ollama model", "llama3.2:1b")

if st.button("Analyze Logs"):
    if upload is not None:
        name, text = upload.name, upload.getvalue().decode("utf-8", errors="replace")
    else:
        name, text = sample, (SAMPLES / sample).read_text()
    report = analyze_log(text.splitlines(), get_kb(), use_llm=use_llm, model=model)

    st.text(f"Analyzed: {name}")
    s = report["stats"]
    cols = st.columns(4)
    cols[0].metric("SSH events", s["events"])
    cols[1].metric("Failed logins", s["failed"])
    cols[2].metric("Accepted logins", s["accepted"])
    cols[3].metric("Unique IPs", s["unique_ips"])

    st.subheader("Summary")
    st.write(report["summary"])
    st.caption(f"Summary mode: {report['mode']}. HIGH = likely compromise or an active attack; "
               "MEDIUM = suspicious activity worth reviewing.")

    if s["failed_by_ip"]:
        st.subheader("Failed attempts per IP")
        st.bar_chart(dict(s["failed_by_ip"]))

    st.subheader("Findings")
    if not report["items"]:
        st.success("No suspicious authentication activity found.")
    for item in report["items"]:
        f = item["finding"]
        (st.error if f.severity == "high" else st.warning)(f"{f.severity.upper()}: {f.title}")
        st.code("\n".join(f.evidence), language=None)  # a code block never renders markdown from log text
        st.markdown(f"**What it means:** {item['meaning']}")
        if item["response"]:
            st.markdown(f"**Recommended response:** {item['response']}")
        with st.expander("Retrieved knowledge"):
            for entry, score in item["hits"]:
                st.markdown(f"**{entry.title}** ({attack_id(entry)}, match {score:.2f})")
