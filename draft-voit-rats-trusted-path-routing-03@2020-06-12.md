---
title: Trusted Path Routing
abbrev: trust-path
docname: draft-voit-rats-trusted-path-routing-03
stand_alone: true
ipr: trust200902
area: Security
wg: RATS Working Group
kw: Internet-Draft
cat: std
pi:
  toc: yes
  tocdepth: 2
  sortrefs: yes
  symrefs: yes

author:
- ins: E. Voit
  name: Eric Voit
  org: Cisco Systems, Inc.
  abbrev: Cisco
  email: evoit@cisco.com

normative:
  RFC8639: event-stream-subscription
  
  crypto-types:  
    target: https://datatracker.ietf.org/doc/draft-ietf-netconf-crypto-types/
    title: "Common YANG Data Types for Cryptography"
    date: 2020-05-20

  TPM1.2:
    target: https://trustedcomputinggroup.org/resource/tpm-main-specification/
    title: "TPM 1.2 Main Specification"
    author:
      -
        ins: TCG
        name: Trusted Computing Group
    date: 2003-10-02
  TPM2.0:
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
    title: "TPM 2.0 Library Specification"
    author:
      -
        ins: TCG
        name: Trusted Computing Group
    date: 2013-03-15

  RATS-Arch:  
    target: https://tools.ietf.org/html/draft-ietf-rats-architecture-02
    title: "Remote Attestation Procedures Architecture"
    date: 2020-07-03

  RATS-YANG:  
    target: https://datatracker.ietf.org/doc/draft-ietf-rats-yang-tpm-charra/
    title: "A YANG Data Model for Challenge-Response-based Remote Attestation Procedures using TPMs"
    date: 2020-01-07

informative:
  RFC3748: EAP
  I-D.ietf-idr-segment-routing-te-policy: SR-TE
  I-D.birkholz-rats-tuda: TUDA
  
  stream-subscription:  
    target: https://tools.ietf.org/html/draft-birkholz-rats-network-device-subscription-00
    title: "Attestation Event Stream Subscription"
    date: 2020-06-03
  
  I-D.ietf-lsr-flex-algo: FlexAlgo
  
  RATS-Device:
    target: https://tools.ietf.org/html/draft-ietf-rats-tpm-based-network-device-attest-00
    title: "Network Device Remote Integrity Verification"
    author:
      -
        ins: G. Fedorkow
      -
        ins: E. Voit
        name: Eric Voit
      -
        ins: J. Fitzgerald-McKay
        name: Jessica Fitzgerald-McKay

  MACSEC:
    target: https://1.ieee802.org/security/802-1ae/ 
    title: "802.1AE: MAC Security (MACsec)"
    author:
      -
        ins: M. Seaman
        name: Mick Seaman
    date: 2006-01-01
  IEEE-802.1X:
    target: https://standards.ieee.org/standard/802_1X-2010.html
    title: "802.1AE: MAC Security (MACsec)"
    author:
      -
        ins: G. Parsons
        name: Glenn Parsons
    date: 2020-01-01

--- abstract

There are end-users who believe encryption technologies like IPSec alone are insufficient to protect the confidentiality of their highly sensitive traffic flows.  These end-users want their flows to traverse devices which have been freshly appraised and verified. This specification describes Trusted Path Routing.  Trusted Path Routing protects sensitive flows as they transit a network by forwarding traffic to/from sensitive subnets across network devices recently appraised as trustworthy.  

--- middle

#  Introduction 

There are end-users who believe encryption technologies like IPSec alone are insufficient to protect the confidentiality of their highly sensitive traffic flows.   These customers want their highly sensitive flows to be transported over only network devices recently verified as trustworthy. 

With the inclusion of TPM based cryptoprocessors into network devices, it is now possible for network providers to identify potentially compromised devices as well as potentially exploitable (or even exploited) vulnerabilities.  Using this knowledge, it then becomes possible to redirect sensitive flows around these devices.  

Trusted Path Routing (TPR) provides a method of establishing Trusted Topologies which only include trust-verified network devices.  This specification describes a distributed variant of TPR.  With this variant, membership in a Trusted Topology is established and maintained via an exchange of Stamped Passports at the link layer between peering network devices. As links to Attesting Devices are appraised as meeting at least a minimum set of formally defined Trustworthiness Levels, the links are then included as members of this Trusted Topology.  {{-FlexAlgo}} is then used to propogate topology state throughout an IGP domain.  IP Packets to and from end-user designated Sensitive Subnets are then forwarded into this Trusted Topology at each IGP boundary.

The specification works under the following assumptions:

1. All network devices supports the TPM remote attestation profile as laid out in {{RATS-Device}}
1. A {{-FlexAlgo}} topology spans network devices within an IGP domain. 
1. One or more Verifiers continuously appraise the set of network devices in the IGP domain, and the Verifiers canse return the Attestation Results back to the attesting network device.
1. 802.1x or MACSEC is used to communicate EAP credentials containing a Stamped Passport between network peers.

Beyond the distributed variant of TPR, there is another method to accomplish Trusted Path Routing.  A controller-based TPR variant is described in the appendicies. 


# Terminology

## Terms
The following terms are imported from {{RATS-Arch}}: 
Attester, Evidence, Passport, Relying Party, and Verifier. 

The following terms at imported from {{RFC8639}}: Event Stream.

Newly defined terms for this document:

Attested Device --
: a device where a Verifier's most recent appraisal of Evidence has returned a Trustworthiness Vector.   

Stamped Passport --
: a bundle of Evidence which includes at least signed Attestation Results from a Verifier, and two independent TPM quotes from an Attester.

Sensitive Subnet --
: an IP address range where IP packets to or from that range must only have their IP headers and encapsulated payloads accessible/visible only by Attested Devices. 

Transparently-Transited Device --
: a network device within an IGP domain where any packets passed into that IGP domain are completely opaque at Layer 3 and above. 

Trusted Topology --
: A topology which includes only Attested Devices and Transparently-Transited Devices.

Trustworthiness Level --
: a specific quanta of trustworthiness which can be assigned by a Verifier.   

Trustworthiness Vector --
: a set of Trustworthiness Levels assigned during a single assessment cycle by a Verfier using Evidence and Claims related to an Attested Device.  The vector is included within Attestation Results. 

## Requirements Notation

{::boilerplate bcp14}

# Distributed Trusted Path Routing

## Trusted Topology

To be included in a Trusted Topology, a Stamped Passport {{passport-section}} is assembled by an Attested Device.  This Stamped Passport will include the most recent Verifier provided Trustworthiness Vector {{vector-section}} for that Attested Device.  Upon receiving and appraising this Stamped Passport as part of link layer authentication, the Relying Party decides if this link should be added to a Trusted Topology.  

When enough links on enough Relying Parties have been so appraised, a Trusted Topology will now exist within an IGP domain.  And traffic exchanged with Sensitive Subnets can be forwarded into that Trusted Topology from all edges of an IGP domain.

~~~
              .--------.             .---------.
              | Hacked |             | Edge    |       
 .---------.  | Router |             | Router  |    
 | Router  |  |        |             |         |    
 |         |  |   trust>-------------<no_trust |
 | no_trust>--<trust   | .--------.  |         |----Sensitive
 |         |  '--------' |   trust>==<trust    |    Subnet 
 |    trust>=============<trust   |  |         |    
 '---------'             |        |  '---------' 
                         | Router | 
                         '--------' 
~~~
{: #fig-distributed title="Distributed Trusted Path Topology Assembly"}

{: #vector-section}
## Trustworthiness Vector

For distributed TPR to operate, specific Appraisal Results need to be consistently interpreted by Relying Party network devices.  The following set of Trustworthiness Levels are defined for this purpose: 

| Trustworthiness Level | Definition |
| hw-authentic | A Verifier has appraised an Attester as having authentic hardware |
| fw-authentic | A Verifier has appraised an Attester as having authentic firmware |
| hw-verification-fail | A Verifier has appraised an Attester has failed its hardware or firmware verification |
| identity-verified | A Verifier has appraised and verified an Attester's unique identity |
| identity-fail | A Verifier has been unable to assess or verify an Attester's unique identity |
| boot-verified | A Verifier has appraised an Attester as Boot Integrity Verified |
| boot-verification-fail | A Verifier has appraised an Attester has failed its Boot Integrity verification |
| files-verified | A Verifier has appraised an Attester's file system, and asserts that it recognizes relevant files |
| file-blacklisted | A Verifier has found a file on an Attester which should not be present |

More that one Trustworthiness Level may be contained within Appraisal Results.  As a result, a single Trustworthiness Vector which contains a sequenced list of Trustworthiness Levels MUST be returned within the Attestation Results.  The establishment of this Vector follows the following logic on the Verifier.

~~~

Start: TPM Quote Received, log recevied, or appraisal timer expired

Step 0: set Trustworthiness Vector = Null

Step 1: Is there sufficient fresh signed evidence to appraise?
   (yes) - No Action
   (no) -  Goto Step 6
   
Step 2: Appraise Hardware Integrity
   (if hw-verification-fail) - push onto vector, Goto Step 6
   (if hw-authentic) - push onto vector
   (if fw-authentic) - push onto vector
   (if not evaluated, or insufficient data to conclude: take no action)

Step 3: Appraise attester identity
   (if identity-verified) - push onto vector
   (if identity-fail) - push onto vector
   (if not evaluated, or insufficient data to conclude: take no action)

Step 4: Appraise boot integrity
   (if boot-verified) - push onto vector
   (if boot-verification-fail) - push onto vector
   (if not evaluated, or insufficient data to conclude: take no action)

Step 5: Appraise filesystem integrity
   (if files-verified) - push onto vector
   (if file-blacklisted) - push onto vector
   (if not evaluated, or insufficient data to conclude: take no action)

Step 6: Assemble Attestation Results, and push to Attester 

End

~~~

{: #passport-section}
## Stamped Passport

Critical to the establishment and maintenance of a Trusted Topology is the Stamped Passport.  These are exchanged between peering network devices over a link layer protocol like 802.1x.  As link layer protocols often continuously re-authenticate, this allows fresh evidence to be constantly appraised. {{passport-section}} provides a protocol independent process for Stamped Passport generation and evaluation.  {{passport-instance}} later in the document binds the Stamped Passport to specific link layer protocols, YANG models, and authentication methods.

The composite nature of the Stamped Passport exposes multiple dimensions of an attesting router's security posture to a network peer.  Specifically, using capabilities defined within {{RATS-YANG}} and {{stream-subscription}}, the following can be established about the Attester:

* its hardware-based identity,
* the Trustworthiness Vector according to its most recent Verifier appraisal, 
* the amount of time which has passed since the Attester has been assigned the Trustworthiness Vector, and
* if the PCRs haven't changed, the Attester's current Trustworthiness Vector

With this information, the Relying Party peer can make nuanced decisions.  For example, when the Attester's legitimate hardware identity credentials can be verified, it might choose to accept link layer connections and forward generic Internet traffic.  Additionally, if the Attester's Trustworthiness Vector is acceptable to the Relying Party, and it hasn't been too long since the Verifier has provided a Stamped Passport, the Relying Party can include that link in a Trusted Topology.

As the process described above repeats across the set of links within the IGP domain, Trusted Topologies can be extended and maintained.  Traffic to and from Sensitive Subnets is then identified at the edges of the IGP domain and passed into this Trusted Topology.

The prerequisites for this solution to work are:

* A Trusted Topology such as one established by {{-FlexAlgo}} exists in an IGP domain for the forwarding of Sensitive Subnet traffic.  This Topology will carry traffic across a set of devices which currently meet at least minimum Trustworthiness Vectors.
* Customer designated Sensitive Subnets and their requested Trustworthiness Vectors have been identified and associated with external interfaces to/from the edge of a network. Traffic to a Sensitive Subnet can be passed into the Trusted Topology.
* Verifiers A and B (in the figure below) are able to verify {{TPM1.2}} or {{TPM2.0}} signatures of an Attester. 
* Verifier A can establish the Trustworthiness Vector of an Attester and return a signed result to that Attester.
* An Attester can assemble a Stamped Passport for Verifier B. 
* Verifier B trusts information signed by Verifier A.
* Within a network, a Relying Party is able to use affinity to include/exclude links as part of the Trusted Topology based on this appraisal.

~~~
       .--------------.
       |  Verifier A  |
       '--------------'
           ^     (2)
           |     Verifier A signed Trustworthiness Vector
      Evidence    |
          (1)     V
        .-------------.                           .---------------.
        | Attester    |                           | Relying Party |
        |  (Router)   |<------------------nonce(3)|  / Verifier B |
        |  .-----.    |                           |   (Router)    |
        |  | TPM |    |(4)-Stamped Passport------>|               |
        |  '-----'    |                           |      (5)      |
        '-------------'                           '---------------'
~~~
{: #fig-passport title="Stamped Passport Generation and Appraisal"}

In {{fig-passport}} above, Evidence from a TPM1.2 or TPM2.0 is generated and signed by that TPM. This Evidence is appraised by Verifier A, and the Attester is given a Trustworthiness Vector which is signed and returned as Attestation Results to the Attester.   Later, when a request comes in from a Relying Party, the Attester assembles and returns three independently signed elements of Evidence.  These three comprise the Stamped Passport which when taken together allow Verifier B to appraise and set the current Trustworthiness Vector of the Attester.

More details on the mechanisms used in the construction and verification of the Stamped Passport match to the numbered steps of {{fig-passport}}:

1.  An Attester sends a signed TPM Quote which includes PCR measurements to Verifier A at time(x).  This specification does not mandate a specific mechanism for the delivery this TPM Quote.  Alternatives to consider include:

    * The \<attestation\> stream defined in {{stream-subscription}}.  Note: this mechanism is recommended as it will minimize the interval between when a PCR change is made in a TPM, and when the PCR change appraisal is incorporated within a subsequent Stamped Passport.  
    * The RPCs defined in device {{RATS-YANG}}

2.  Verifier A appraises (1), then sends the following items back to that Attester as Attestation Results:

    1.  the Trustworthiness Vector of an Attester,
    2.  the signature from the TPM Quote of (1),
    3.  the Public AIK Key which it used to validate the TPM Quote of (1), and    
    4.  a Verifier signature across (2.1), (2.2) and (2.3).

3.  A nonce known to the Relying Party is received by the Attester at time(y).  
4.  The Attester generates and sends a Stamped Passport.  This Stamped Passport includes:

    1. (1)
    2. (2)        
    3. New signed, verifiably fresh PCR measurements at time(y), which incorporates the nonce from (3).   
    
5.  On receipt of (4), the Relying Party makes its determination of how the Stamped Passport will impact adjacencies within a Trusted Topology.  The decision process is:

    1. Verify that (4.3) includes the nonce from (3).
    2. Use a local certificate to validate the signature (4.2).    
    3. Verify the TPM signature within (4.2) matches the signature of (4.1).
    4. Use the key of (2.3) to validate the signatures of (4.1) and (4.3).  
    5. Failure of (5.1) through (5.4) means the link does not meet minimum validation criteria, therefore appraise the link as having a null Trustworthiness Vector, and additionally jump to step (5.9).
    6. If selected PCR values/hash of (1) match (4.3), then Relying Party can accept (2.1) as the link's Trustworthiness Vector.  
    7. When the PCR values/hash are different, and not much time has passed between time(x) and time(y), the Relying Party can either accept any previous Trustworthiness Vector, or attempt to acquire a new Stamped Passport.  Where {{stream-subscription}} is used, it should only be a few seconds before a new Attestation Results should be delivered to an Attester via (2).   
    8. When the PCR values are different, but there is a large time gap between time(x) and time(y), the link should be assigned a null Trustworthiness Vector.
    9. Based on the link's Trustworthiness Vector:
    
        1. include it within any Trusted Topology which accepts that Trustworthiness Vector.
        2. remove it from any Trusted Topology which does not accept that Trustworthiness Vector.




{: #passport-instance}
## Passport Protocol Bindings 

This section provides details of how a Stamped Passport described in {{passport-section}} interacts with link layer protocols like {{MACSEC}} or {{IEEE-802.1X}}, YANG subscriptions {{RFC8639}}, and {{-EAP}} methods.  Additional linkages to the YANG module defined in {{YANG-Module}} are described.

~~~
    .--------------.             
    |  Verifier A  |
    '--------------'     
        ^     (2)           
        |     Verifier A signed Attestation Results @time(x) (
    Evidence(  |  Trustworthiness Level,   
    TpmQuote   |  signature from TpmQuote@time(x) )               
    @time(x))  |                        
       (1)     V                        
     .-------------.                           .---------------.
     |  Attester   |<------nonce @time(y)---(3)| Relying Party |
     |    .-----.  |                           |  / Verifier B |
     |    | Tpm |  |(4)-Stamped Passport ( --->|   (Router)    |
     |    '-----'  |     TpmQuote@time(y),     |     (5)       |
     '-------------'     TpmQuote@time(x),     '---------------'
                         Verifier A signed Attestation Results @time(x) )
~~~
{: #fig-generation title="Details of Stamped Passport Generation"}

{{fig-generation}} above expands upon the previously described {{fig-passport}}.  The numbering in both figures is the same.

Step (1)

Verifier A acquires Evidence including a TPM Quote from the attester via {{RATS-YANG}} and/or {{stream-subscription}}.

Step (2)

As the Evidence changes, Verifier A evaluates the totality of the Evidence received.  Verifier A then sets the Trustworthiness Vector of the Attester.  Subsequently it sends back a signed Attestation Result which includes the Trustworthiness Vector and the signature sent as part of (1) from the Attester.  It is this signature which allows the Trustworthiness Vector to be later provably associated with a recent TPM Quote.

The delivery of Attestation Results back to the Attester can be done via a YANG operational datastore write of the following objects:

~~~ YANG
  +--rw attestation-results!?
     +--rw trustworthiness-vector*        identityref
     +--rw timestamp                      yang:date-and-time
     +--rw tpmt-signature?                binary
     +--rw public-key-format              identityref
     +--rw public-key                     binary
     +--rw public-key-algorithm-type      identityref
     +--rw verifier-signature?            binary
     +--rw verifier-signature-key-name?   binary
~~~
{: #fig-results-tree title="Attestation Results Tree"}


Step (3)

At time(y) a Relying Party makes a Link Layer connection request to an Attester via a protocol such as {{MACSEC}} or {{IEEE-802.1X}}.  This connection request must include {{-EAP}} credentials.  Specifics of the EAP credentials are TBD.  If there is no central distribution of time via {{-TUDA}} a nonce must be included to ensure freshness of a response.

This step can repeat periodically independently of any subsequent iteration (1) and (2). This allows for periodic reauthentication of the link layer in a way not bound to the updating of Verifier A's Attestation Results.  

Step (4) 

Upon receipt of (3), a Stamped Passport is generated as per {{passport-section}}, and sent to the Relying Party.

Step (5)

Upon receipt of (4), the Relying Party verifies the Stamped Passport as per {{passport-section}}.  Most often, the relevant PCR values at time(x) will be the same as the PCR values at time(y).  In this case, the Relying Party can simply accept the Trustworthiness Vector assigned by the Verifier A.  When the PCR values are different, and not much time has passed between time(x) and time(y), the Relying Party can either accept the previous Trustworthiness Vector, or attempt another EAP request in a few seconds as new Attestation Results are delivered by Step (2).   When there is a large time gap between time(x) and time(y) and the PCR values are different, the Attester should be given a blank Trustworthiness Vector.

Based on the link's Trustworthiness Vector, the Relying Party may adjust the link affinity of the corresponding {{-FlexAlgo}} topology.


{: #YANG-Module} 
## YANG Modules

This YANG module imports modules from {{RATS-YANG}} and {{crypto-types}}. 


~~~~ YANG
<CODE BEGINS> ietf-attestation-results-vector@2020-06-16.yang
{::include /media/sf_rats/ietf-attestation-results-vector@2020-06-16.yang}
<CODE ENDS>
~~~~ 

The model above also imports ietf-asymmetric-algs.yang.  This algorithm type content was included within -v14 NETCONF's iana-crypto-types.yang.  Unfortunately this model and the needed algorithms failed to make the -v15 used WGLC.  As a result, a file which meets the intents of the authors is included below within draft-voit-rats-trusted-path-routing.  With luck, perhaps someone will steward this as a separate draft.

~~~~ YANG
<CODE BEGINS> ietf-asymmetric-algs@2020-06-12.yang
{::include /media/sf_rats/ietf-asymmetric-algs@2020-06-12.yang}
<CODE ENDS>
~~~~ 


# Security Considerations

Successful attacks on an IGP domain Verifier has the potential of affecting traffic on the Trusted Topology.

For Distributed Trusted Path Routing, links which are part of the FlexAlgo are visible across the entire IGP domain.  Therefore a compromised device will know when it is being bypassed.

Access control for the objects in {{fig-results-tree}} should be tightly controlled so that it becomes difficult for the Stamped Passport to become a denial of service vector.

--- back
 
 
# Centralized Trusted Path Routing

Trusted Path Routing does not require integration with Routing protocols as is done with Distributed Trusted Path Routing.  It is also possible for a Controller to choose a path through a network.  This architural alternative is called Centralized Trusted Path Routing.

With Centralized Trusted Path Routing, trusted end-to-end paths are pre-assigned through a network provider domain.  Along these paths, Evidence of potentially transited components has been assessed.  Each path is guaranteed to only include devices which achieve at least a minimum set of a formally defined Trustworthiness Levels.  

In this alternative, a controller-based Verifier ensures communications with Sensitive Subnets traverses a Trusted Topology within the controller's routing domain.  To do this, the Verifier continuously acquires Evidence about each potentially transited device.  This access is done via the context established within {{RATS-Device}}.  The controller then appraises the Evidence and decides on a Trustworthiness Vector for each device.  The controller then identifies end-to-end path(s) which avoid any devices which are unable to meet the minimum Trustworthiness Levels.  Finally, the controller provisions network policy so that flows to and from Sensitive Subnet to use just these end-to-end paths.

Evidence passed to the Verifier which are used to establish a device's Trustworthiness Vector will include but is not limited to: 

* An Attester's security measurements being extended into {{TPM1.2}} or {{TPM2.0}} compliant Platform Configuration Registers (PCR). 
* An Attester's current PCR measurements. 

The prerequisites for this solution are:

1. Customer designated Sensitive Subnet ranges and their acceptable Trustworthiness Vectors have been identified and associated with external interfaces to/from the edge of a routing domain.
1. A Verifier which can continuously acquire Evidence and appraise the Trustworthiness Levels of all network devices within the routing domain. 
1. A Verifier which continuously optimizes a set of network paths/tunnels. These paths must traverse only Attested Devices or Transparently-Transited Devices while on their way to an egress interface for a routing Domain.
1. A Verifier which can provision and maintain the set of Sensitive Subnets associated with specific network paths/tunnels.

{{fig-centralized}} provides a network diagram of where these four sit within a network topology.

~~~
     .------------------------------------------------.         
     |            Verifier + Relying Party  (3)       |
     '------------------------------------------------'  
       (4) ^        ^        ^         ^        ^ (4) 
        |  |       (2)       |         |        |  |
        |  |   .-------.     |         |       (2) V
        V (2)  |Hacked |    (2)       (2)     .--------.        
    .--------. |Router | .-------. .-------.  | Edge   |   
    | Edge   | |(Attest| |Router | |Switch |  | Router |    
    | Router | | =Fail)| |(Attest| |(Attest|  | (Attest|         
    |        | '-------' |  =OK) | |  =OK) |  |   =OK) |         
   (1)   path==================================>      (1)--- Sensitive
    |       <==================================path    |      Subnet
    '--------'           '-------' '-------'  '--------'
~~~
{: #fig-centralized title="Centralized Trusted Path Routing"}

The feature functionality describing how to achieve (1) - (4) are outside the scope of this specification.  The reasoning is that each of these can be accomplished via technologies specified elsewhere.  For example, in step (4), it is possible for a Verifier to provision each ingress device with the set of Sensitive Subnets for which traffic would be placed into a specific {{-SR-TE}} tunnel.  As another example, consider prerequisite (2): network devices can stream changes in Evidence to a Verifier by establishing an {{RFC8639}} subscription to the \<attestation\> Event Stream as described in {{stream-subscription}}. 

# Acknowledgements

Shwetha Bhandari, Henk Birkholz, Chennakesava Reddy Gaddam, Sujal Sheth, Peter Psenak, Nancy Cam Winget, Ned Smith, Guy Fedorkow, Liang Xia. 

#  Change Log

\[THIS SECTION TO BE REMOVED BY THE RFC EDITOR.\]

v02-v03

* The Attester's AIK is included within the Stamped Passport.  This eliminates the need to provision to AIK certificate on the Relying Party.

v01-v02

* Extracted the attestation stream, and placed into draft-birkholz-rats-network-device-subscription
* Introduced the Trustworthiness Vector

v00-v01

* Move all FlexAlgo terminology to {{passport-instance}}. This allows {{passport-section}} to be more generic.
* Edited Figure 1 so that (4) points to the egress router.
* Added text freshness mechanisms, and articulated configured subscription support. 
* Minor YANG model clarifications.
* Added a few open questions which Frank thinks interesting to work.

# Open Questions

Do we need functional requirements on how to handle traffic to/from Sensitive Subnets when no Trusted Topology exists between IGP edges?  The network typically can make this unnecessary.    For example it is possible to construct a local IPSec tunnel to make untrusted devices appear as Transparently-Transited Devices.  This way Secure Subnets could be tunneled between FlexAlgo nodes where an end-to-end path doesn't currently exist.  However there still is a corner case where all IGP egress points are not considered sufficiently trustworthy.

