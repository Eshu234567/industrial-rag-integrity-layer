@echo off
title Beyond Metadata Filtering - Industrial RAG Integrity Layer (Phase-II Demo)
echo ============================================================================
echo   Beyond Metadata Filtering: Authorization-Integrity Layer for Industrial RAG
echo   Starting Live Demonstration Server on http://localhost:8050 ...
echo ============================================================================
start "" http://localhost:8050
python "%~dp0app.py"
pause
