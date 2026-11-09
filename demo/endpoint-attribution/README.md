# Outbound attribution: synthetic example

English | [中文](README.zh-CN.md)

This is a signed synthetic example, built from public verification records. It
uses `PUBLIC-ENDPOINT-FIXTURE-CANARY` and `/fixture/secret.txt`; it sends no data to
an external service. Use it to inspect how the reader separates three attribution
questions when a body match has more than one possible source read.

```sh
agentprov demo endpoint-attribution
```

[Open the selected attribution record](https://byteyellow.github.io/AgentProvenance/en/replay.html?run=ui-endpoint-candidates&lens=data-flow-taint&detail=raw&live=0&selected=sha256%3A44fe36c9defe9293755c49b45c2223d11f6ba5ef32aba86b7f6f4b50fcef2768#inspection).

## Read the three evidence layers

| Question | Saved result | Evidence to inspect |
| --- | --- | --- |
| Does the outbound body contain the marker? | Body match | Captured content and marker reference |
| Which file read supplied it? | Two candidates | Exact path, read-before-capture ordering and content hash |
| Which execution performed the transmission? | Unknown | Available scope evidence and its missing identity fields |

The rule is `agentprov.endpoint_attribution/v2`. Both read candidates remain
visible with their references. Selecting a candidate opens the corresponding
record; the body match does not choose a read by timestamp alone.

## Replay and verification

The compressed bundle, DSSE attestation and public key ship together. Signature
and graph checks validate the saved example on import. Its synthetic origin is
stated in the gallery and this guide.

For a real captured workflow with intent and TLS detail, open
[Evidence attribution: inspect and repair](../evidence-attribution/README.md).
