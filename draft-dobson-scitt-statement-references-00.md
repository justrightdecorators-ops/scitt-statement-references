---
title: "References Between Signed Statements in SCITT: Problem Statement, Composition at Registration, and Design Direction"
abbrev: "SCITT Statement References"
docname: draft-dobson-scitt-statement-references-00
category: info
submissiontype: IETF
ipr: trust200902
area: Security
workgroup: SCITT
keyword:
 - SCITT
 - transparency
 - statement identification
 - composition
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    fullname: Justin Antony Dobson
    organization: Monop Content (sebbi.pro)
    email: justrightdecorators@gmail.com

normative:
  RFC2119:
  RFC8174:
  RFC9052:
  RFC9943:

informative:
  RFC7942:
  I-D.gruszka-scitt-statement-identification:
  I-D.mih-sokolov-scitt-payload-binding:
  I-D.nobuo-scitt-protected-object-binding:
  I-D.moore-scitt-ciris-ceg:
  I-D.wright-verdict-record:
  I-D.yetis-scitt-figure-receipts:
  I-D.dobson-ai-decision-receipt:
  I-D.ietf-scitt-receipts-mmr-profile:
  I-D.le-comparing-derived-identifiers:
  PINTO-NOTE:
    title: "Statement identification for IETF 127"
    author:
      fullname: Tiago Pinto
    date: 2026-09-25
    target: https://mailarchive.ietf.org/arch/msg/scitt/SsHbIj2bDs9TdiAsZ37NFUqt5TM/

--- abstract

Signed Statements registered with a SCITT Transparency Service
increasingly rely on other Signed Statements: a decision record cites the
published figure it used, a verdict record cites the records it checked,
and a companion statement in a registrable algorithm stands in for an
original the service cannot verify. This document consolidates the
problem as it has been discussed in the SCITT working group, adopts the
requirements for statement references already set out in
draft-gruszka-scitt-statement-identification, and adds one property those
requirements make possible but do not define: composition at
registration, where a Transparency Service refuses a Signed Statement
whose references it cannot resolve. It names the one scoping question the
working group needs to settle, and proposes a design direction for an
open design team to work out.

--- middle

# Introduction

{{RFC9943}} defines how Signed Statements are registered with a
Transparency Service and how Receipts prove their inclusion. It treats
payloads as opaque and leaves Registration Policies to the operator
(Section 5.1.1 of {{RFC9943}}). It defines no statement identifier.

A growing number of profiles need one Signed Statement to rely on
another. Cases raised on the SCITT list in November 2026 include:

* an AI agent's decision record naming the published figure statement it
  relied on {{I-D.dobson-ai-decision-receipt}}
  {{I-D.yetis-scitt-figure-receipts}};
* a verdict record, written by a party that wrote neither record, citing
  each record it checked {{I-D.wright-verdict-record}};
* a companion statement in a registrable algorithm carrying the
  identifier of an original signed with an algorithm the service cannot
  yet verify {{I-D.moore-scitt-ciris-ceg}}.

Each works within one implementation. Between implementations it fails
unless both read the reference under the same rule.

Existing work covers much of the ground.
{{I-D.gruszka-scitt-statement-identification}} sets out requirements and
test cases for statement references (its A1 to A5). It defines no common
reference format; it uses `[alg, scheme, digest]` and a ToBeSigned scheme
over the COSE Sig_structure as illustrations. The design direction below
is where this document proposes promoting them. {{I-D.mih-sokolov-scitt-payload-binding}} defines a
derivation and comparison contract for typed digest references.
{{I-D.nobuo-scitt-protected-object-binding}} defines Statement
References, Relationship Edges and Statement Graphs. {{PINTO-NOTE}}
proposes that any digest-based statement reference specify its
derivation and comparison context, and frames the charter question.

This document does not replace any of these. It does three things:

1. states the problem in one place, with what has been observed in
   implementations;
2. adds composition at registration, which none of the above defines;
3. asks the working group to settle the scoping question in
   {{open-question}} so that a design team can proceed.

It does not define a wire format.

## Requirements Language

{::boilerplate bcp14-tagged}

# Terminology

This document uses Signed Statement, Transparency Service, Receipt,
Issuer and Registration Policy as defined in {{RFC9943}}, and statement
reference, identification scheme and reference matching as defined in
{{I-D.gruszka-scitt-statement-identification}}.

Referencing Statement:
: A Signed Statement that carries one or more statement references.

Referenced Statement:
: The target of a statement reference.

# Problem Statement

## One Statement, Several Identifiers

One logical statement can be re-encoded, gain or lose an unprotected
header, and be registered with several Transparency Services, each
issuing its own entry handle and Receipt (Section 6.3 of {{RFC9943}}).
Schemes in use today cover different parts of it:

1. a digest over the COSE Sig_structure ({{RFC9052}}, Section 4.4), the
   ToBeSigned scheme of {{I-D.gruszka-scitt-statement-identification}};
2. a digest over the protected header and payload under a profile's own
   encoding, as in {{I-D.moore-scitt-ciris-ceg}};
3. a digest over the complete object as transmitted;
4. an identifier derived from registration in one service.

Schemes 1 and 2 select the same statements and produce different values.
They select the same statements because {{I-D.moore-scitt-ciris-ceg}}
(Section 5.2) fixes external_aad to empty, so neither depends on anything
outside the protected header and payload.
This has been observed in practice: in November 2026 the identifier of the
Appendix B.3 statement of {{I-D.moore-scitt-ciris-ceg}} was reproduced
exactly under scheme 2, while the ToBeSigned digest of the same protected
header and payload gave a different value. A reference made under one
scheme is not found by an implementation that only knows the other.

## What Equality Shows

{{I-D.le-comparing-derived-identifiers}} sets out the principle of
deciding what equality is meant to conclude before choosing the
derivation. {{PINTO-NOTE}} applies it to SCITT and asks what identifier
equality is meant to support. The schemes above support
different conclusions: equality under schemes 1 and 2 shows the same
signed content; under scheme 3, the same octets; under scheme 4, the same
registration in one named service. A relying party that does not know
which of these a match shows cannot know what the reference proves.

Companion statements are a live case, and they involve two separate
choices. What the companion carries, the identifier alone or the
identifier together with a digest of the original's full bytes, is a
question of what equality shows (C1). Where it carries it, protected
header or payload, is the open question in {{open-question}}. The two
companions registered in November 2026 for the Appendix B.3 statement of
{{I-D.moore-scitt-ciris-ceg}} differ in both at once, so they are not a
clean header-versus-payload pair: a header companion could carry the
full-bytes digest too. Because the identifier leaves out the signature
(Section 5.2 of {{I-D.moore-scitt-ciris-ceg}}), an entry for a companion
carrying the identifier alone shows that a statement with that identifier
was cited at registration, not that a signed statement existed. One
carrying the full-bytes digest also pins the original's octets, signature
included.

## Composition at Registration

A Registration Policy can make composition a property of the log rather
than only of the verifier: a Transparency Service can refuse to register
a Referencing Statement until each Referenced Statement it cites is
already registered with it. This needs no change to {{RFC9943}}. It has
been implemented, and a statement citing an unregistered statement has
been refused with no entry made.

Such a policy depends on two things the references must provide: the
service must be able to find the references without understanding the
payload, and it must be able to resolve each one under a scheme it
implements.

# Requirements

This document adopts requirements A1 to A5 of
{{I-D.gruszka-scitt-statement-identification}} for statement references.
In particular, a reference names its identification scheme, and missing
inputs or an unsupported scheme cannot produce a successful match (A1).

It adds the following, for composition at registration:

C1:
: Each identification scheme MUST state what equality under it shows, for
  example the same signed content, the same octets, or the same
  registration in a named Transparency Service {{PINTO-NOTE}}. The list
  is not closed: Section 5.3 of
  {{I-D.gruszka-scitt-statement-identification}} distinguishes four
  identities, and its Table 1 adds payload-only and canonical-encoding
  objects.

C2:
: A Registration Policy MAY refuse a Referencing Statement whose
  references cannot be resolved to Signed Statements already registered
  with that Transparency Service. Such a policy MUST state which
  identification schemes it resolves, and MUST refuse, not accept, a
  reference under a scheme it does not implement. Since Section 5.1.1.1 of
  {{RFC9943}} requires Registration Policies to be registered as Signed
  Statements, that registered policy statement is where the schemes are
  stated. A by-product of C2 is that every Referenced Statement was
  registered before the Referencing Statement that cites it. That is
  registration order, not issuance order (Section 9.1 of {{RFC9943}}).

C3:
: When a Registration Policy refuses a Referencing Statement under C2, it
  MUST register nothing and SHOULD state which reference failed to
  resolve.

C4:
: A reference under a registration-derived scheme MUST identify the
  Transparency Service whose registration it names, and is not by itself
  sufficient for C2 in any other service.

C5:
: The design MUST NOT require any change to the architecture in
  {{RFC9943}}, to SCRAPI, or to the adopted Verifiable Data Structure
  profiles.

# The Open Question {#open-question}

{{PINTO-NOTE}} (Section 3) frames the charter question, and
{{I-D.gruszka-scitt-statement-identification}} (A2) presents the same
choice as one of scope. The note asks about relationship edges and their
relation semantics; this document narrows the question to the reference
half and leaves the relationship vocabulary out:

* Is it enough to define reusable reference semantics that each profile
  carries as it chooses? Then only a verifier that understands the
  profile can find the references, and a Transparency Service cannot
  apply C2 without understanding every payload.

* Or must a generic verifier, and a Transparency Service applying C2, be
  able to find references without understanding the payload? Then the
  working group must define the minimum that such a verifier can read,
  which points to a protected header parameter.

Both give real guarantees, and they differ. A reference in the payload
stays with the content, and a verifier waits for a missing Referenced
Statement. A reference in the protected header lets the log refuse at
registration. This document asks the working group to decide which it
needs. Under the first answer a service can still apply C2 to the
profiles it reads, since Section 6.3 of {{RFC9943}} (step 2) lets it
validate the payload for policies tied to a content type. What only the
second answer gives is generic composition: C2 for any profile, without
understanding its payload.

# Candidate Design Direction

Offered as a starting point for the design team, not a conclusion.

* Use the reference form `[alg, scheme, digest]` of
  {{I-D.gruszka-scitt-statement-identification}}, with the ToBeSigned
  scheme as a common default. It is computable from any COSE_Sign1
  given its payload and external_aad, without understanding the payload;
  A1 asks a ToBeSigned scheme to state both, and {{RFC9943}} illustrates
  detached payloads. It survives attached Receipts, and survives
  re-signing only while the protected header bytes stay the same: a new
  alg or kid gives another ToBeSigned (Section 6 of
  {{I-D.gruszka-scitt-statement-identification}}), which is the companion
  case.

* Give each scheme a statement of what its equality shows (C1).

* If the working group chooses generic discovery, define a protected
  header parameter carrying an array of references, and the Registration
  Policy behaviour in C2 and C3. If it chooses profile-carried semantics,
  define the semantics only, and leave C2 to profiles that put references
  where a service can read them.

* Keep ordering in time between statements out of scope. It is a
  separate property, depending on the time sources available to each
  party.

# Out of Scope

Whether the content of a Referenced Statement is true; the order in time
between statements; transitive trust along chains of references;
relationship vocabulary, which {{I-D.nobuo-scitt-protected-object-binding}}
addresses.

# Implementation Status

This section records known implementations at the time of writing,
following {{RFC7942}}, and is to be removed before publication.

* sebbi.pro Transparency Service: implements the MMR receipts profile
  {{I-D.ietf-scitt-receipts-mmr-profile}}; accepts an optional
  protected-header array of references under the ToBeSigned scheme;
  resolves a reference under the scheme the reference names (the
  ToBeSigned scheme, or the identifier of {{I-D.moore-scitt-ciris-ceg}}),
  never by trying one value under several schemes; refuses
  registration of a statement whose references are not registered,
  registering nothing.

* A conformance checker (version 2): it takes references in the form
  `[alg, scheme, digest]`, reads candidates strictly, keeps MATCH,
  NO_MATCH, INDETERMINATE and UNSUPPORTED apart, uses the fixed-empty
  external_aad variant unless one is supplied, and reproduces two known
  answers (statement 01 of Appendix A.1 of
  {{I-D.gruszka-scitt-statement-identification}}, and the Appendix B.3
  statement of {{I-D.moore-scitt-ciris-ceg}}). On the published cases of
  Section 6 it agrees on ref_usable, match and is_scitt in all 58 checks
  it runs; it verifies no signatures.

* An independent reader of Section 6 of
  {{I-D.gruszka-scitt-statement-identification}}, written from the text
  of that section without reference to its author's checker, reproduces
  all 63 published results (54 cases and 9 variants) of revision -04
  under the profile sid-ed25519-strict, using the Python standard library
  only. Revision -05 (24 November 2026) keeps A1 to A5 and their numbers.

* Three test vectors composing agent decision records with publisher
  figure statements, and verdict records over them written by a third
  party, have been published and checked independently. Interoperability
  work on them moves to the design team.

# Security Considerations

The security considerations of
{{I-D.gruszka-scitt-statement-identification}} apply: a match is not a
trust decision, and a stable reference can act as a correlator.

A Registration Policy applying C2 learns which statements a Referencing
Statement relies on. Issuers who need to keep that relationship private
should not use references a service can read.

An implementation that accepted an unsupported scheme as resolved would
let a Referencing Statement into the log citing something that was never
checked. C2 requires refusal.

Registration-derived identifiers depend on the service that assigned
them, which can present different views to different parties. They should
be used with that service's consistency and witnessing mechanisms, and not
as the only identifier of signed content (C4).

# IANA Considerations

This document makes no request of IANA. A future document may request a
COSE header parameter for references, depending on the answer to
{{open-question}}.

--- back

# Acknowledgments
{:numbered="false"}

This document builds on the statement identification work of Konrad
Gruszka, on Tiago Pinto's note on derivation and comparison context and his
review of the first text and checker, and
on the payload-binding and protected-object-binding drafts. Thanks to
Eric Moore, Ziya Yetiş, Darren Wright, Dick Brooks, Thomas Meister and
Andre Neumann for discussion and independent checks on the SCITT list,
and to Jon Geater for setting the direction.
