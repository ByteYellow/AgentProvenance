"""AgentProvenance Python SDK alias.

This package re-exports the lightweight evaluator SDK from `agentprov_eval` so
RL users can write `from agentprov import rule, Signal`.
"""

from agentprov_eval import *  # noqa: F401,F403
