"""
modules/ai_chat.py
Interactive AI chat — ask questions about your scan results.

Works with any configured AI provider (same as ai_triage.py).
Maintains full conversation history so follow-up questions have context.

Usage:
    paramspecter https://target.com --mode full --ai-chat
    paramspecter https://target.com --ai-chat --ai-provider groq
"""

import json
import os
import sys
import time
from typing import Dict, List, Optional

from .ai_triage import AIProvider, build_provider, auto_detect_provider, _build_triage_prompt
from ..utils import log, log_section, col, C


CHAT_SYSTEM_PROMPT = """\
You are an expert penetration tester and bug bounty hunter.
The user has just run an automated recon scan with ParamSpecter and you have
been given the full scan results as context. Your job is to help them
understand the findings, suggest attack paths, write exploit payloads,
explain vulnerabilities, recommend tools and commands, and help prioritise
what to investigate next.

Be specific, technical, and concise. Reference exact URLs, parameters,
and technologies from the scan results. When suggesting commands, make
them copy-paste ready for the specific target.

The scan results are provided at the start of the conversation and remain
in context for all follow-up questions.
"""

WELCOME_MSG = """\
  ┌─────────────────────────────────────────────────────┐
  │  ParamSpecter AI Chat                               │
  │  Ask anything about your scan results.              │
  │                                                     │
  │  Examples:                                          │
  │    what are the highest priority targets?           │
  │    write a sqlmap command for the login page        │
  │    explain the CORS finding                         │
  │    is there anything that looks like a quick win?   │
  │    what nuclei templates should I run first?        │
  │                                                     │
  │  Commands:  /exit  /clear  /save  /findings         │
  └─────────────────────────────────────────────────────┘
"""


class AIChat:
    """
    Interactive multi-turn conversation about scan results.
    Keeps full message history so context is maintained.
    """

    def __init__(self, provider: Optional[AIProvider] = None,
                 provider_name: str = "", model: str = ""):
        self.provider = provider or build_provider(provider_name, model)
        self.history: List[Dict] = []   # [{role, content}, ...]
        self._scan_context: str  = ""
        self._output_dir: str    = "."
        self._base_domain: str   = "target"

    def available(self) -> bool:
        return self.provider is not None and self.provider.available()

    def load_scan(self, scanner) -> None:
        """Build context string from scanner results."""
        self._scan_context  = _build_triage_prompt(scanner)
        self._output_dir    = scanner.output_dir
        self._base_domain   = scanner.base_domain

    def _chat(self, user_message: str) -> str:
        """Send a message, get a reply, update history."""
        # First message includes full scan context
        if not self.history:
            first_user = (
                "Here are my scan results:\n\n"
                f"{self._scan_context}\n\n"
                f"My first question: {user_message}"
            )
            self.history.append({"role": "user", "content": first_user})
        else:
            self.history.append({"role": "user", "content": user_message})

        # Build the full message list for the API call
        reply = self._call_provider()
        self.history.append({"role": "assistant", "content": reply})
        return reply

    def _call_provider(self) -> str:
        """Call the AI provider with full conversation history."""
        p = self.provider

        # Providers that support multi-turn natively
        from .ai_triage import (
            AnthropicProvider, OpenAIProvider, GroqProvider,
            MistralProvider, OllamaProvider, GeminiProvider, CustomProvider
        )

        try:
            if isinstance(p, AnthropicProvider):
                import json as _json
                from urllib.request import urlopen, Request
                payload = {
                    "model":      p.model,
                    "max_tokens": p.max_tokens,
                    "system":     CHAT_SYSTEM_PROMPT,
                    "messages":   self.history,
                }
                headers = {
                    "x-api-key":         p.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                }
                resp = p._http_post(p.API_URL, headers, payload)
                return resp["content"][0]["text"]

            elif isinstance(p, (OpenAIProvider, GroqProvider, MistralProvider, CustomProvider)):
                messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + self.history
                payload = {
                    "model":      p.model,
                    "max_tokens": p.max_tokens,
                    "messages":   messages,
                }
                headers = {
                    "Authorization": f"Bearer {p.api_key}",
                    "Content-Type":  "application/json",
                }
                resp = p._http_post(p.api_url, headers, payload)
                return resp["choices"][0]["message"]["content"]

            elif isinstance(p, OllamaProvider):
                messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + self.history
                payload = {
                    "model":    p.model,
                    "messages": messages,
                    "stream":   False,
                    "options":  {"num_predict": p.max_tokens},
                }
                headers = {"Content-Type": "application/json"}
                resp = p._http_post(f"{p.base_url}/api/chat", headers, payload)
                return resp["message"]["content"]

            elif isinstance(p, GeminiProvider):
                # Gemini uses a different multi-turn format
                contents = []
                for msg in self.history:
                    role = "user" if msg["role"] == "user" else "model"
                    contents.append({"role": role, "parts": [{"text": msg["content"]}]})
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{p.model}:generateContent?key={p.api_key}"
                )
                payload = {
                    "system_instruction": {"parts": [{"text": CHAT_SYSTEM_PROMPT}]},
                    "contents": contents,
                    "generationConfig": {"maxOutputTokens": p.max_tokens},
                }
                headers = {"Content-Type": "application/json"}
                resp = p._http_post(url, headers, payload)
                return resp["candidates"][0]["content"]["parts"][0]["text"]

            else:
                # Generic fallback — single turn with full history concatenated
                full_context = CHAT_SYSTEM_PROMPT + "\n\n"
                for msg in self.history:
                    prefix = "User: " if msg["role"] == "user" else "Assistant: "
                    full_context += prefix + msg["content"] + "\n\n"
                return p.chat(CHAT_SYSTEM_PROMPT, full_context)

        except Exception as e:
            return f"[AI Error: {e}]"

    def _handle_command(self, cmd: str) -> Optional[str]:
        """Handle slash commands. Returns output string or None to exit."""
        cmd = cmd.strip().lower()

        if cmd == "/exit":
            return None   # signal to exit

        elif cmd == "/clear":
            self.history.clear()
            return col("  Conversation cleared. Scan context will be re-sent on next message.", C.YELLOW)

        elif cmd == "/save":
            ts    = time.strftime("%Y%m%d_%H%M%S")
            path  = os.path.join(self._output_dir,
                                 f"paramspecter_{self._base_domain}_{ts}_chat.md")
            lines = [f"# ParamSpecter AI Chat — {self._base_domain}\n",
                     f"**Provider:** {self.provider.NAME} / {self.provider.model}\n",
                     f"**Saved:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n"]
            for msg in self.history:
                role = "**You**" if msg["role"] == "user" else "**AI**"
                # Skip the verbose scan context in the saved file
                content = msg["content"]
                if "Here are my scan results:" in content:
                    idx = content.find("My first question:")
                    if idx != -1:
                        content = content[idx + len("My first question:"):].strip()
                lines.append(f"\n{role}\n\n{content}\n\n---")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            return col(f"  Chat saved → {path}", C.GREEN)

        elif cmd == "/findings":
            # Quick summary of finding counts from history context
            return col(
                "  Re-run with --ai-triage for a full findings summary.\n"
                "  Or ask: 'summarise all findings by severity'", C.CYAN
            )

        elif cmd == "/help":
            return (
                col("  Commands:\n", C.CYAN) +
                "    /exit     — quit chat\n"
                "    /clear    — clear conversation history\n"
                "    /save     — save conversation to markdown file\n"
                "    /findings — show finding counts\n"
                "    /help     — show this message"
            )

        return col(f"  Unknown command: {cmd}  (try /help)", C.YELLOW)

    def _print_reply(self, text: str) -> None:
        """Pretty-print AI reply with syntax highlighting."""
        print()
        in_code = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code = not in_code
                print(col("  " + line, C.GRAY))
                continue
            if in_code:
                print(col("  " + line, C.YELLOW))
            elif stripped.startswith("#"):
                print(col("  " + line, C.CYAN + C.BOLD if hasattr(C, "BOLD") else C.CYAN))
            elif stripped.startswith("- ") or stripped.startswith("* "):
                print(col("  " + line, C.GREEN))
            else:
                print("  " + line)
        print()

    def run(self, scanner=None) -> None:
        """Start the interactive chat loop."""
        if not self.available():
            log("CHAT", col(
                "No AI provider configured. Set an API key env var.\n"
                "  Run: paramspecter --ai-status", C.RED
            ), C.RED)
            return

        if scanner:
            self.load_scan(scanner)

        pname = self.provider.NAME
        model = self.provider.model

        log_section(f"AI CHAT — {pname.upper()} / {model}")
        print(col(WELCOME_MSG, C.CYAN))

        prompt_str = col("  You > ", C.GREEN + C.BOLD if hasattr(C, "BOLD") else C.GREEN)

        while True:
            try:
                user_input = input(prompt_str).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not user_input:
                continue

            # Slash commands
            if user_input.startswith("/"):
                result = self._handle_command(user_input)
                if result is None:
                    break
                print(result)
                continue

            # Regular question — call AI
            print(col(f"\n  {pname} is thinking...", C.GRAY), end="\r")
            t0    = time.monotonic()
            reply = self._chat(user_input)
            elapsed = time.monotonic() - t0

            # Clear "thinking" line
            print(" " * 40, end="\r")

            # Print reply
            print(col(f"  AI [{elapsed:.1f}s] ", C.CYAN), end="")
            self._print_reply(reply)

        print(col("\n  Chat session ended.", C.YELLOW))
