# tollbooth demo cast — drives the REAL Claude Code hook adapter (no upstream
# server needed). Every line on screen is genuine `tollbooth` output.
#
# Reproduce from the repo root:  vhs demo/demo.tape
# Produces: assets/demo.gif (README) and assets/demo.webm (site / crisp video).

Output assets/demo.gif
Output assets/demo.webm

Set Shell "bash"
Set FontSize 19
Set Width 1320
Set Height 840
Set Padding 26
Set Margin 16
Set BorderRadius 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 15ms

# --- off-camera setup: PATH to the venv binary, clean prompt, fresh log ---
Hide
Type "export PATH=$PWD/.venv/bin:$PATH; export PS1='❯ '; rm -f demo/demo-audit.jsonl; clear"
Enter
Sleep 700ms
Show

Type "# tollbooth governs every tool call an AI agent makes — in real time."
Enter
Sleep 1.2s
Type "# each command below feeds a real hook event to the live policy + DLP engine."
Enter
Sleep 1.6s

Type "# 1) the agent tries to pipe a remote script straight into a shell:"
Enter
Sleep 900ms
Type "tollbooth hook pre -c demo/tollbooth.yaml < demo/events/01-bash-curl-pipe-sh.json | jq"
Enter
Sleep 2.8s

Type "# 2) the agent is about to leak an AWS key into a GitHub issue:"
Enter
Sleep 900ms
Type "tollbooth hook pre -c demo/tollbooth.yaml < demo/events/02-mcp-egress-secret.json | jq"
Enter
Sleep 3.2s

Type "# 3) a tool result comes back carrying live credentials:"
Enter
Sleep 900ms
Type "tollbooth hook post -c demo/tollbooth.yaml < demo/events/03-post-result-secret.json | jq"
Enter
Sleep 3.2s

Type "# 4) a safe call? tollbooth stays out of the way — no output, defers to Claude:"
Enter
Sleep 900ms
Type "tollbooth hook pre -c demo/tollbooth.yaml < demo/events/04-bash-ok.json"
Enter
Sleep 2s

Type "# the raw key never appears in any output — nor anywhere in the audit log:"
Enter
Sleep 900ms
Type "grep -c AKIAIOSFODNN7EXAMPLE demo/demo-audit.jsonl"
Enter
Sleep 2.2s

Type "# and every decision is hash-chained and tamper-evident:"
Enter
Sleep 900ms
Type "tollbooth audit verify --log demo/demo-audit.jsonl"
Enter
Sleep 4s
