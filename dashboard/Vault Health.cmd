@echo off
title Vault Health
node "%~dp0server.js"
if errorlevel 1 pause
