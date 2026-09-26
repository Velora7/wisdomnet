Threat Model

Author: Kalkidan Belachew
Institution: Bahir Dar University
Project: WisdomNet, Autonomous Deception Based Early Warning and Incident Triage


1. Purpose of this document

This document records the threat model that WisdomNet was designed against. It explains what the system is intended to detect, what it is not intended to detect, and why the scoring weights in engine/scoring.yaml have the values they do. The weights are not arbitrary. Each one is tied to a specific assumption about attacker behaviour that is stated below.


2. Scope

2.1 In scope

WisdomNet is designed to detect the early stages of an external network intrusion against a university campus network. The specific activities it detects are:

1. Network scanning and service discovery against decoy services
2. Credential attacks such as password guessing and brute force against decoy services
3. Successful authentication to a decoy service using fabricated credentials
4. Command execution after obtaining access to a decoy service
5. Attempts to access files or data through a decoy service

These five activities correspond to the five stages of the attacker state machine implemented in engine/state_machine.py.

2.2 Out of scope

The following threats are explicitly out of scope. They are not detected by WisdomNet and are not claimed to be.

1. Denial of service attacks. WisdomNet does not measure traffic volume and has no rate limiting logic.
2. Supply chain attacks. WisdomNet does not inspect software packages, build systems or update channels.
3. Insider threats from users who have legitimate access to production systems. Deception sensors only observe interaction with services that no legitimate user should touch.
4. Zero day exploits. The sensors in WisdomNet are not real services and cannot be exploited by a specific vulnerability. They only observe that an interaction attempt was made.
5. Physical attacks, social engineering and other non network threats.
6. Attacks that do not interact with decoy services. If an attacker stays entirely within production infrastructure, WisdomNet will not see them.


3. Assumptions

The threat model rests on four assumptions. If any of them does not hold, the risk scores may not reflect real world severity.

Assumption 1. No legitimate user should access a decoy service.

This is the foundation of any deception system. The decoy services are placed on an isolated network segment and are not advertised through DNS, documentation or any user facing interface. Any interaction with a decoy service is therefore suspicious by default.

In a real deployment this assumption is enforced by network segregation, not by policy alone. The deception sensors sit on a VLAN that is not routable from user subnets except through monitoring infrastructure.

Assumption 2. Attackers progress through identifiable stages.

WisdomNet assumes that a serious attack moves through recognisable stages: reconnaissance, credential access, service access, command execution and data access. This assumption is supported by the MITRE ATT&CK framework, which documents these stages as common patterns in real intrusions. It does not hold for every possible attacker, but it holds for the great majority of commodity attacks that target university networks.

Assumption 3. Event sequence carries more information than event volume.

A single port scan is not evidence of an intrusion attempt. Twenty port scans from the same source followed by five failed logins followed by a successful login is a much stronger signal. WisdomNet scores events with this in mind. The scoring caps in engine/incident.py limit how much any single event type can contribute, and the sequence bonus in engine/scoring.yaml rewards reaching later stages of the state machine.

Assumption 4. The sensor may be compromised.

A deception sensor is a natural target for a competent attacker. If the sensor is compromised, the attacker could attempt to alter or delete the event log. WisdomNet addresses this with SHA 256 hash chaining. Each event includes the hash of the previous event, so deleting or modifying any event breaks the chain at that point. Verification is performed by collector/verify.py.


4. Adversary model

WisdomNet is designed against three classes of adversary, each with different capabilities and different observable behaviour.

4.1 Automated scanner

A script or tool that scans a range of IP addresses looking for open ports and responsive services. This adversary is not targeting WisdomNet specifically. It is looking for any host that responds. Observable behaviour is a burst of connection attempts across multiple ports from a single source over a short period. The state machine assigns this adversary to the RECON state and the severity is normally Informational.

4.2 Credential attacker

An adversary that has identified a service and is attempting to authenticate to it using guessed or default credentials. This adversary has moved past reconnaissance into active exploitation. Observable behaviour is a series of failed authentication attempts against the same service, often with common usernames such as root, admin or test. The state machine assigns this adversary to the CREDENTIAL state. If the attempts succeed, the state advances to ACCESS.

4.3 Post exploitation attacker

An adversary that has obtained access to a decoy service and is now exploring it. Observable behaviour is the execution of commands after successful authentication, followed by attempts to read files or access data. This adversary is the highest priority because the intent is no longer in doubt. The state machine assigns this adversary to EXECUTION or EXFIL ATTEMPT states, and severity is normally Critical.


5. Scoring rationale

Each event type in engine/scoring.yaml has a weight. The weights are listed below with the reasoning behind each one. The scale is 0 to 100 for individual events, with the sequence bonus applied separately.

service discovery, weight 10. Passive reconnaissance. Low skill, low intent signal. Common background noise on any internet facing network.

http probe, weight 15. Active reconnaissance. Slightly higher than service discovery because the attacker is looking at content, not just ports. Still commodity behaviour.

ftp login attempt, weight 20. A credential attempt against a low value protocol. FTP is rarely legitimate on modern networks, so any interaction is mildly suspicious.

db connection attempt, weight 20. A connection attempt to a decoy database. Similar in intent to FTP but marginally higher risk because databases hold structured data.

ssh failed login, weight 25. A credential attack has begun. This is a step above reconnaissance because the attacker has committed to authentication attempts.

ssh successful login, weight 70. Access has been obtained. Even though the credentials are fabricated, the attacker believes they have valid access. This is a strong signal of intent.

command execution, weight 90. Post exploitation. The attacker is issuing commands. This is close to the highest priority activity a deception sensor can observe.

credential access, weight 100. The attacker is attempting to read credential material. This carries the highest business impact because credentials often unlock multiple systems.

file access, weight 100. The attacker is attempting to read data files. Equivalent business impact to credential access in most contexts.

5.1 Sequence bonus

When the state machine advances a source to the EXECUTION state or beyond, WisdomNet adds a sequence bonus of 40 to the incident score. The bonus exists because a completed attack chain is more significant than the sum of its parts. An attacker who typed a command has already demonstrated reconnaissance, credential attack and access. Scoring those stages individually understates the total severity.

5.2 Scoring caps

engine/incident.py applies a per event type cap to scoring. The default cap is three occurrences of the same event type from the same source. Beyond the cap, additional events are still recorded and still shown in the dashboard breakdown, but they do not increase the score.

This cap reflects the assumption that an attacker who has already shown a certain behaviour does not become proportionally more dangerous by repeating it. A source that scans one port and a source that scans one hundred ports are not ten times apart in intent. The cap prevents the score from being dominated by volume.

5.3 Severity thresholds

The final score maps to a severity band in engine/state_machine.py.

Score 0 to 30 maps to Informational.
Score 31 to 70 maps to Medium.
Score 71 to 140 maps to High.
Score above 140 maps to Critical.

The thresholds were chosen so that a single reconnaissance burst stays Informational, a credential attack reaches High, and only a completed attack chain reaching EXECUTION or beyond becomes Critical.


6. MITRE ATT&CK mapping

WisdomNet maps a small subset of observable events to MITRE ATT&CK techniques. The full framework is not implemented and is not claimed to be. The mapping is deliberately narrow so that every entry is accurate.

service discovery maps to Network Service Discovery, technique ID T1046.
http probe maps to Network Service Discovery, technique ID T1046.
ssh failed login maps to Brute Force, technique ID T1110.
ftp login attempt maps to Brute Force, technique ID T1110.
db connection attempt maps to Brute Force, technique ID T1110.
ssh successful login maps to Valid Accounts, technique ID T1078.
credential access maps to Valid Accounts, technique ID T1078.
command execution maps to Command and Scripting Interpreter, technique ID T1059.
file access maps to File and Directory Discovery, technique ID T1083.


7. Known limitations

1. Source IP addresses in the Docker based demonstration environment are rewritten to the Docker gateway address. In a real deployment with routed traffic, this would not occur.
2. The fake SSH shell accepts any password. This is intentional so that post exploitation behaviour can be captured, but it means the system does not distinguish between trivial and sophisticated credential attacks.
3. The sensors do not perform any form of active response. Recommended responses in the dashboard are advisory only.
4. WisdomNet is not a replacement for an enterprise SIEM. It is a complementary layer intended to sit alongside one.


8. Summary

The scoring weights in WisdomNet are derived from a specific threat model that assumes no legitimate user interacts with the decoy services, that attackers progress through identifiable stages, that sequence carries more information than volume, and that the sensor itself may be compromised. Each weight is justified by the corresponding adversary capability and business impact. The system is deliberately narrow in scope. It detects external attackers interacting with deception sensors, and it does not attempt to address threats outside that scope.
