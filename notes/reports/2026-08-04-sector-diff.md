# Cross-Sector Differential Analysis — 2026-08-04

_Window: last 24h. Baseline: 30d preceding the window. Figures computed deterministically; narrative by local LLM._

## Sector Differentials

The sectors exhibit distinct patterns in terms of who attacks them and how, as evidenced by the ports targeted, countries involved, ASNs, honeypot services, and reputation coverage.

- **Petrochemical**: This sector is heavily targeted on port 5900 (VNC), with significant traffic also seen on ports 389 (LDAP) and 22 (SSH). The majority of the attacks come from the United States, Canada, and The Netherlands. Notable ASNs include DigitalOcean, OVH SAS, and Plus Hosting Grupa d.o.o. Honeypots like "Beelzebub" and "ConPot" are frequently hit. Reputation coverage is low at 15.1%, indicating a significant blind spot.

- **Medical Technology**: The sector sees heavy traffic on port 80 (HTTP) and 8443 (HTTPS). Attacks originate primarily from The Netherlands and the United States, with ASNs like Pfcloud UG (haftungsbeschrankt), GTHost, and TechTies Inc. Honeypots such as "Beelzebub" and "Heralding" are frequently targeted. Reputation coverage is higher at 49.6%, but still leaves room for unknown threats.

- **General Hive**: This sector has very limited traffic compared to others, with most events targeting port 64298. The United States dominates the attack landscape here. Google LLC and Cloudflare, Inc. are among the ASNs involved. Reputation coverage is at 0%, indicating a complete blind spot for this sector.

- **Remote Management (RMM)**: This sector sees significant traffic on ports 22 (SSH) and 5900 (VNC). The Netherlands and the United States are major sources of attacks, with ASNs like TechTies Inc. and OVH SAS being prominent. Honeypots such as "Beelzebub" and "Cowrie" are frequently targeted. Reputation coverage is high at 57.8%.

- **VoIP / Telephony**: This sector sees traffic on ports 22 (SSH) and 5060 (SIP). The United States, The Netherlands, and France are major sources of attacks. ASNs like TechTies Inc., OVH SAS, and Amazon.com, Inc. are involved. Honeypots such as "Cowrie" and "Mailoney" are frequently targeted. Reputation coverage is moderate at 31.4%.

## Targeted vs Indiscriminate

Using concentration and sector count, the following actors appear to be focused on specific sectors rather than sweeping across all:

- **Petrochemical**: The IP addresses 170.101.101.98, 204.76.203.12, 204.76.203.91, and 204.76.203.77 are concentrated on the medical technology sector with a concentration of 1.0, indicating targeted attacks rather than broad sweeps.

- **Medical Technology**: The IP addresses 170.101.101.98, 204.76.203.12, and 204.76.203.91 are concentrated on the medical technology sector with a concentration of 1.0.

- **General Hive**: The IP address 76.165.200.190 is a notable sweeper that targets multiple sectors but has a high concentration (0.984) towards the general hive, indicating it's primarily focused on this sector.

## Reputation Blind Spots

The entities with no reputation classification that stand out by volume or novelty include:

- **38.134.40.217**: This IP address has 51,322 events exclusively targeting medical technology and is novel. It deserves attention due to its high volume of attacks in a single sector.

- **152.179.140.153**: With 24,630 events concentrated on the petrochemical sector, this IP address has no reputation classification but shows significant activity.

- **8.211.130.186**: This IP address targets the petrochemical sector exclusively and is novel with 15,504 events. It deserves investigation due to its concentration on a single sector.

## Assessment

The data indicates that there are substantial blind spots in reputation coverage for sectors like general hive (0%) and petrochemical (15.1%). The high volume of attacks targeting specific ports (e.g., 5900, 8443) and the concentration on certain sectors suggest targeted campaigns rather than broad scanning activities. Notably, entities with no reputation classification are making significant impacts, particularly in medical technology and petrochemical sectors. These blind spots should be prioritized for further investigation to identify potential new threats or actors not yet covered by existing reputation feeds.

## Summary
| Metric | Value |
|---|---|
| IPs examined | 500 |
| Sector-exclusive | 387 (77.4%) |
| Cross-sector sweepers (4+ sites) | 15 |
| New vs baseline | 48 |
| No reputation label at all | 437 |
| → of those, novel or fully concentrated | 25 |

## Sector Profiles
| Sector | Events | Unique IPs | Rep. coverage | Top ports | Top honeypots |
|---|---|---|---|---|---|
| petrochemical | 2,219,022 | 7,957 | 15.1% | 5900, 389, 22, 3283 | Heralding, Beelzebub, H0neytr4p |
| medical technology | 2,075,525 | 6,418 | 49.6% | 80, 8443, 22, 5900 | Galah, Beelzebub, H0neytr4p |
| general hive | 389,691 | 31 | 0.0% | 64298, 137, 64295, 11434 | Honeytrap |
| remote management (RMM) | 214,692 | 7,198 | 57.8% | 22, 5900, 443, 23 | Beelzebub, Cowrie, Tanner |
| VoIP / telephony | 134,736 | 5,552 | 31.4% | 22, 5060, 443, 25 | Cowrie, Sentrypeer, Mailoney |

## Reputation-Blind Queue
_High-volume, novel, or single-sector entities that NO reputation feed classifies. These are the actors the existing 82-100% enrichment coverage structurally cannot surface._
| IP | Events | Sector | Concentration | New? |
|---|---|---|---|---|
| `38.134.40.217` | 51,322 | medical technology | 100% | **yes** |
| `152.179.140.153` | 24,630 | petrochemical | 100% | **yes** |
| `38.76.219.69` | 22,528 | petrochemical | 100% | **yes** |
| `8.211.130.186` | 15,504 | petrochemical | 100% | **yes** |
| `91.233.10.193` | 13,397 | petrochemical | 100% | **yes** |
| `186.241.104.72` | 11,269 | petrochemical | 100% | **yes** |
| `119.148.8.66` | 7,547 | VoIP / telephony | 100% | **yes** |
| `167.172.240.176` | 5,113 | petrochemical | 100% | **yes** |
| `103.231.56.55` | 4,692 | petrochemical | 100% | **yes** |
| `132.226.13.196` | 2,797 | medical technology | 100% | **yes** |
| `137.220.155.194` | 2,748 | petrochemical | 100% | **yes** |
| `178.218.163.232` | 2,600 | petrochemical | 100% | **yes** |
| `178.218.166.48` | 2,431 | petrochemical | 100% | **yes** |
| `178.218.160.153` | 2,324 | petrochemical | 100% | **yes** |
| `151.240.66.245` | 1,973 | medical technology | 100% | **yes** |

## Fully Sector-Concentrated Actors
| IP | Events | Sector (100%) | Reputation | New? |
|---|---|---|---|---|
| `170.101.101.98` | 380,345 | medical technology | **none** | no |
| `204.76.203.12` | 359,693 | medical technology | known attacker | no |
| `204.76.203.91` | 301,628 | medical technology | known attacker | no |
| `204.76.203.77` | 174,866 | medical technology | known attacker | no |
| `147.182.159.182` | 103,381 | petrochemical | **none** | no |
| `167.99.186.169` | 103,150 | petrochemical | **none** | no |
| `134.122.21.135` | 98,579 | petrochemical | **none** | no |
| `167.99.11.20` | 98,135 | petrochemical | **none** | no |
| `129.212.181.73` | 90,135 | petrochemical | **none** | no |
| `137.184.121.249` | 90,041 | petrochemical | known attacker | no |
| `192.241.141.178` | 85,694 | petrochemical | known attacker | no |
| `157.245.114.249` | 85,186 | petrochemical | **none** | no |
| `157.230.91.199` | 81,381 | petrochemical | known attacker | no |
| `38.134.40.217` | 51,322 | medical technology | **none** | **yes** |
| `109.51.157.192` | 32,487 | petrochemical | **none** | no |

## Coordinated ASN Campaigns
_Three or more IPs from one provider. Individually small and unflagged; collectively a single campaign._
| ASN / org | IPs | Events | Sector | Concentration | New IPs | Unlabelled |
|---|---|---|---|---|---|---|
| Plus Hosting Grupa d.o.o. | 43 | 77,207 | petrochemical | 100% | 16 | 43 |
| GSL Networks Pty LTD | 4 | 4,741 | medical technology | 100% | 3 | 4 |
| Datacamp Limited | 20 | 59,209 | medical technology | 100% | 2 | 20 |
| Alibaba (US) Technology Co., Ltd. | 17 | 29,413 | petrochemical | 100% | 2 | 17 |
| DigitalOcean, LLC | 19 | 936,276 | petrochemical | 100% | 1 | 14 |
| Pfcloud UG (haftungsbeschrankt) | 3 | 836,187 | medical technology | 100% | 0 | 0 |
| 1337 Services GmbH | 30 | 127,065 | medical technology | 100% | 0 | 30 |
| Latitude.sh LTDA | 14 | 63,404 | medical technology | 100% | 0 | 14 |
| Latitude.sh | 12 | 55,170 | medical technology | 100% | 0 | 12 |
| Tencent Building, Kejizhongyi Aven | 44 | 35,289 | petrochemical | 100% | 0 | 43 |

## Port Skew
| Port | Events | Sectors | Dominant | Concentration |
|---|---|---|---|---|
| 5900 | 1,835,601 | 4 | petrochemical | 97% |
| 80 | 1,303,871 | 4 | medical technology | 99% |
| 8443 | 459,921 | 4 | medical technology | 97% |
| 22 | 354,145 | 4 | medical technology | 44% |
| 64298 | 337,892 | 2 | general hive | 100% |
| 389 | 97,830 | 4 | petrochemical | 100% |
| 3283 | 83,779 | 4 | petrochemical | 100% |
| 443 | 29,533 | 4 | petrochemical | 33% |
| 23 | 24,424 | 4 | petrochemical | 45% |
| 161 | 24,186 | 4 | petrochemical | 99% |
| 3389 | 12,219 | 4 | petrochemical | 88% |
| 25 | 9,694 | 4 | medical technology | 47% |

## ASN Skew
| ASN / org | Events | Sectors | Dominant | Concentration |
|---|---|---|---|---|
| DigitalOcean, LLC | 943,526 | 4 | petrochemical | 100% |
| Pfcloud UG (haftungsbeschrankt) | 836,923 | 4 | medical technology | 100% |
| GTHost | 380,395 | 4 | medical technology | 100% |
| TechTies Inc. | 199,899 | 4 | medical technology | 47% |
| OVH SAS | 142,986 | 4 | petrochemical | 56% |
| 1337 Services GmbH | 127,191 | 4 | medical technology | 100% |
| Cogent Communications, LLC | 83,121 | 4 | medical technology | 76% |
| Plus Hosting Grupa d.o.o. | 79,864 | 1 | petrochemical | 100% |
| Alibaba (US) Technology Co., Ltd. | 66,619 | 4 | petrochemical | 91% |
| HostPapa | 64,703 | 4 | petrochemical | 84% |
| Latitude.sh LTDA | 63,404 | 1 | medical technology | 100% |
| Banatsync Srl | 62,790 | 4 | medical technology | 50% |
