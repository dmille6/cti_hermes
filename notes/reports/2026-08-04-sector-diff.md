# Cross-Sector Differential Analysis — 2026-08-04

_Window: last 24h. Baseline: 30d preceding the window. Figures computed deterministically; narrative by local LLM._

## Sector Differentials
Sector profiles reveal stark behavioral differences in attacker focus: The medical technology sector (db4lamedtech) faced the highest reputation coverage at **42.3%**, indicating better visibility of attackers targeting it. It saw the most scans on port 80 (1,026,503 events) and port 8443 (447,211 events), with a clear U.S. (>941k events) – Netherlands (>695k events) split as top sources. Notable attackers included ASNs **Pfcloud** (U.S., >564k total events across all sectors) and **GTHost** (null reputation, >380k events), exclusively targeting medical technology in the data provided.

Conversely， the petrochemical sector (db1lapetro) exhibited the lowest reputation coverage at just **16.2%**. This sector was heavily scanned on port 5900 (VNC: **1,807,460 events**), primarily from ASNs like DigitalOcean and OVH SAS in the U.S., Netherlands, Canada， France，and Germany（total>100k events each). ASN **DigitalOcean** dominated this sector with over 957k total events. Notably, reputation-blind attackers targeting petrochemicals included entities with IPs such as 38.134.40.217 and 109.51.157.192, generating thousands of port scans.

Key ports differed significantly by sector： VNC（5900） was dominant in petrochemicals， while HTTP（80） and HTTPs（8443） were key for medical technology. Remote Management (RMM) also saw SSH（port 22 with >110k events） scans， while VoIP focused on SIP ports like 5060。 Honeypot usage patterns also varied， with Heralding、Beelzebub、and Cowrie being heavily targeted in some sectors but not others.

## Targeted vs Indiscriminate
The data indicates a mix of highly concentrated and broad targeting: Over **76.8% (384/500)** of observed IPs were sector-exclusive, demonstrating highly focused attacks rather than indiscriminate sweeps.

High-concentration actors included:
*   **IP 170.101.101.98**: Focused on medical technology， generating over 380k events, with no reputation tagging. This represents a significant potential threat.
*   **IP 204.76.203.12** and **204.76.203.77** (same ASN Pfcloud): Both exclusively targeted medical technology， generating over 359k events respectively, with known reputation tags indicating attacker activity.
*   Multiple IPs associated with ASN **DigitalOcean**: Such as 129.212.181.73、147.182.159.182 and others， that concentrated attacks on petrochemical targets generating thousands of events each, some labelled and some not。

However， indiscriminate sweepers were also present。 Notably, the top sweeper **IP 76.165.200.190** generated a massive **341k+ total events**. While it primarily hit the general hive（336k events）, it still sent substantial scan traffic to multiple sectors - medical technology（1.74k), petrochemicals（1.73k), RMM＞1.68k, and VoIP＞502， showing widespread, non-differentiated scanning behavior。

## Reputation Blind Spots
A significant **85% of all examined IPs (out of 500) have no reputation classification in the feeds**, highlighting critical blind spots. These entities were often highly active or exclusive to specific sectors： 
*   **IPs like 170.101.101.98 and 204.76.203.77** (targeting medical technology exclusively) generated hundreds of thousands of events with NO reputation tags， demanding urgent investigation due to their high volume and specificity。
*   **ASN DigitalOcean, LLC** hosted multiple reputation-blind IPs heavily focused on petrochemical targets （examples: IP 129.212.181.73、IP 147.182.159.182等), and their overall dominance across the data warrants deeper analysis。
*   **ASNs Plus Hosting (Croatia)** 和 ASN Datacamp Limited** also had multiple reputation-blind IPs with high sector concentration（especially for petrochemical and medical technology respectively）. Investigation is needed into the traffic from these ASNs， as they represent unidentified yet potentially significant attack vectors。

These unknown actors, generating substantial activity specifically within target sectors, are arguably the most concerning threats in this dataset because their lack of reputation means feeds have missed classifying them appropriately – they may well be highly sophisticated attackers that other systems simply haven't caught up to。 Further investigation should focus on capturing payloads from these sessions， performing threat hunting against hostnames or indicators observed during these blind attacks, and attempting to classify the behavior using external intelligence sources (e.g. emerging threat reports) or dynamic analysis where appropriate.

## Assessment
Based on this data from the 24-hour window， it appears that a significant shift has occurred in attacker behaviour: While broad scanning still occurs (as exemplified by sweeper IPs hitting multiple sectors and general hives heavily), targeted attacks against specific industries, particularly medical technology and petrochemicals, have considerably increased. The high volume of **reputation-unlabelled traffic originating from major cloud ASNs** targeting these niche sectors is the most prominent concerning change. Immediate action is warranted to investigate the behaviour of these specific reputation-blind IPs (especially top concentrations like 170.101.101.98 and others)， the associated hostnames, and any payloads or commands seen from them。 The sheer volume of traffic from well-known attacker ASNs against critical infrastructure sectors is unacceptable background noise； it represents a high-risk threat requiring prioritization for enhanced monitoring, potential mitigation (e.g., block lists based on JA3/HASSH fingerprints if malicious intent is confirmed), and sharing with relevant CTI communities（OTX、CrowdStrike etc.） for broader attribution。

## Summary
| Metric | Value |
|---|---|
| IPs examined | 500 |
| Sector-exclusive | 384 (76.8%) |
| Cross-sector sweepers (4+ sites) | 16 |
| New vs baseline | 37 |
| No reputation label at all | 427 |
| → of those, novel or fully concentrated | 25 |

## Sector Profiles
| Sector | Events | Unique IPs | Rep. coverage | Top ports | Top honeypots |
|---|---|---|---|---|---|
| petrochemical | 2,164,303 | 7,903 | 16.2% | 5900, 389, 22, 3283 | Heralding, Beelzebub, H0neytr4p |
| medical technology | 1,791,965 | 6,375 | 42.3% | 80, 8443, 22, 5900 | Beelzebub, Galah, H0neytr4p |
| general hive | 387,600 | 27 | 0.0% | 64298, 137, 64295, 49824 | - |
| remote management (RMM) | 249,342 | 7,133 | 60.2% | 22, 5900, 443, 2222 | Beelzebub, Cowrie, Tanner |
| VoIP / telephony | 136,184 | 5,506 | 32.1% | 22, 5060, 443, 25 | Cowrie, Sentrypeer, Mailoney |

## Reputation-Blind Queue
_High-volume, novel, or single-sector entities that NO reputation feed classifies. These are the actors the existing 82-100% enrichment coverage structurally cannot surface._
| IP | Events | Sector | Concentration | New? |
|---|---|---|---|---|
| `38.134.40.217` | 51,322 | medical technology | 100% | **yes** |
| `152.179.140.153` | 24,630 | petrochemical | 100% | **yes** |
| `38.76.219.69` | 14,984 | petrochemical | 100% | **yes** |
| `119.148.8.66` | 7,547 | VoIP / telephony | 100% | **yes** |
| `8.211.130.186` | 5,619 | petrochemical | 100% | **yes** |
| `186.241.104.72` | 5,128 | petrochemical | 100% | **yes** |
| `91.233.10.193` | 5,123 | petrochemical | 100% | **yes** |
| `167.172.240.176` | 5,113 | petrochemical | 100% | **yes** |
| `103.231.56.55` | 4,692 | petrochemical | 100% | **yes** |
| `132.226.13.196` | 2,797 | medical technology | 100% | **yes** |
| `178.218.163.232` | 2,600 | petrochemical | 100% | **yes** |
| `178.218.166.48` | 2,431 | petrochemical | 100% | **yes** |
| `178.218.160.153` | 2,324 | petrochemical | 100% | **yes** |
| `151.240.66.245` | 1,973 | medical technology | 100% | **yes** |
| `178.218.160.146` | 1,785 | petrochemical | 100% | **yes** |

## Fully Sector-Concentrated Actors
| IP | Events | Sector (100%) | Reputation | New? |
|---|---|---|---|---|
| `170.101.101.98` | 380,345 | medical technology | **none** | no |
| `204.76.203.12` | 359,693 | medical technology | known attacker | no |
| `204.76.203.77` | 174,866 | medical technology | known attacker | no |
| `147.182.159.182` | 103,856 | petrochemical | **none** | no |
| `167.99.186.169` | 103,680 | petrochemical | known attacker | no |
| `134.122.21.135` | 99,006 | petrochemical | known attacker | no |
| `167.99.11.20` | 98,356 | petrochemical | **none** | no |
| `129.212.181.73` | 90,415 | petrochemical | **none** | no |
| `137.184.121.249` | 90,293 | petrochemical | known attacker | no |
| `192.241.141.178` | 85,268 | petrochemical | **none** | no |
| `157.245.114.249` | 84,821 | petrochemical | **none** | no |
| `157.230.91.199` | 80,183 | petrochemical | known attacker | no |
| `38.134.40.217` | 51,322 | medical technology | **none** | **yes** |
| `109.51.157.192` | 32,429 | petrochemical | **none** | no |
| `77.239.124.239` | 31,398 | medical technology | known attacker | no |

## Coordinated ASN Campaigns
_Three or more IPs from one provider. Individually small and unflagged; collectively a single campaign._
| ASN / org | IPs | Events | Sector | Concentration | New IPs | Unlabelled |
|---|---|---|---|---|---|---|
| Plus Hosting Grupa d.o.o. | 24 | 47,064 | petrochemical | 100% | 8 | 24 |
| Datacamp Limited | 21 | 60,246 | medical technology | 99% | 2 | 21 |
| Alibaba (US) Technology Co., Ltd. | 17 | 19,473 | petrochemical | 100% | 2 | 17 |
| GSL Networks Pty LTD | 4 | 4,743 | medical technology | 100% | 2 | 4 |
| DigitalOcean, LLC | 20 | 958,341 | petrochemical | 100% | 1 | 14 |
| Pfcloud UG (haftungsbeschrankt) | 3 | 564,112 | medical technology | 100% | 0 | 0 |
| 1337 Services GmbH | 30 | 127,210 | medical technology | 100% | 0 | 30 |
| Latitude.sh LTDA | 14 | 63,572 | medical technology | 100% | 0 | 14 |
| Latitude.sh | 12 | 55,167 | medical technology | 100% | 0 | 12 |
| Tencent Building, Kejizhongyi Aven | 44 | 35,300 | petrochemical | 100% | 0 | 43 |

## Port Skew
| Port | Events | Sectors | Dominant | Concentration |
|---|---|---|---|---|
| 5900 | 1,863,279 | 4 | petrochemical | 97% |
| 80 | 1,040,656 | 4 | medical technology | 99% |
| 8443 | 460,470 | 4 | medical technology | 97% |
| 22 | 381,650 | 4 | medical technology | 41% |
| 64298 | 336,653 | 2 | general hive | 100% |
| 389 | 97,813 | 3 | petrochemical | 100% |
| 443 | 29,720 | 4 | petrochemical | 34% |
| 23 | 23,056 | 4 | petrochemical | 44% |
| 3283 | 14,279 | 4 | petrochemical | 100% |
| 3389 | 12,204 | 4 | petrochemical | 88% |
| 2222 | 10,134 | 4 | remote management (RMM) | 65% |
| 25 | 9,826 | 4 | medical technology | 47% |

## ASN Skew
| ASN / org | Events | Sectors | Dominant | Concentration |
|---|---|---|---|---|
| DigitalOcean, LLC | 965,713 | 4 | petrochemical | 99% |
| Pfcloud UG (haftungsbeschrankt) | 564,853 | 4 | medical technology | 100% |
| GTHost | 380,395 | 4 | medical technology | 100% |
| TechTies Inc. | 227,033 | 4 | medical technology | 42% |
| OVH SAS | 141,704 | 4 | petrochemical | 57% |
| 1337 Services GmbH | 127,335 | 4 | medical technology | 100% |
| Cogent Communications, LLC | 83,513 | 4 | medical technology | 76% |
| HostPapa | 66,151 | 4 | petrochemical | 84% |
| Latitude.sh LTDA | 63,572 | 1 | medical technology | 100% |
| Banatsync Srl | 62,826 | 4 | medical technology | 50% |
| Datacamp Limited | 62,368 | 4 | medical technology | 96% |
| Alibaba (US) Technology Co., Ltd. | 56,700 | 4 | petrochemical | 90% |
