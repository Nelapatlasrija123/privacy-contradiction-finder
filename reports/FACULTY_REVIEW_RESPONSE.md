# Faculty Review Response — Privacy Contradiction Finder

This document records the four questions raised in the faculty review, how we answer each one, and the code changes we made to the project as a result. Every change is covered by automated tests (**122 tests, all passing**).

---

## Summary of Changes

| # | Change | Answers question | Where |
|---|---|---|---|
| 1 | New **Third-Party Sharing** category in the policy analyzer | Q1 | `src/analysis/rule_analyzer.py` |
| 2 | New **tracker SDK detector** (23 known trackers: AdMob, Firebase, Facebook, AppsFlyer, …) | Q1 | `src/analysis/tracker_detector.py` (new) |
| 3 | New **Terms & Conditions analyzer** that links T&C clauses to permissions | Q2 | `src/analysis/terms_analyzer.py` (new) |
| 4 | **Evidence levels** (1–4) on every finding, and a trust score weighted by evidence strength | Q3 | `src/analysis/contradiction_detector.py` |
| 5 | **Seven loopholes** in the analyzer fixed (see the loophole table under Q4) | Q4 | `src/analysis/rule_analyzer.py`, `contradiction_detector.py` |
| 6 | Five missing permissions added: `INTERNET`, `AD_ID`, `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS` | Q1, Q4 | `src/permissions/permission_db.py` |
| 7 | App screen: new optional inputs (SDK list, T&C text, evidence level) and result panels (trackers, T&C clauses, score breakdown) | All | `app.py` |
| 8 | New demo case **"Weather (Hidden Trackers)"** in the sidebar | Q1, Q2 | `sample_data/sample_tracker_app.json` |
| 9 | 51 new tests; README merge-conflict lines removed; test counts corrected | Q4 | `tests/`, `README.md` |

---

## Q1. If the privacy policy doesn't mention data sharing, how can we determine whether the app shares data with third parties?

**Short answer:** The policy alone cannot tell us — silence is not proof either way. We use evidence from *outside* the policy: the third-party SDKs (tracker libraries) bundled inside the app, and the advertising-ID permission.

**Reasoning:** A tracker SDK such as Google AdMob, AppsFlyer, or Firebase Analytics exists *to send data to its company*. If the APK contains one, the app is technically set up to share data with that company. If the policy never mentions sharing, that is an undisclosed-sharing concern. If the policy *denies* sharing, it is a potential contradiction.

**What we built:**
- **Tracker detector** — the user pastes the SDK package list (from an Exodus Privacy report, a jadx package tree, or Gradle dependencies). The tool matches it against 23 known tracker signatures.
- **Third-Party Sharing category** — the policy is now also checked for statements about partners, advertisers, third parties, selling and sharing.
- **`AD_ID` permission** — the Google Advertising ID permission is now recognised as a sharing signal.

**Decision rules:**

| Policy says about sharing | Tracker SDK found in app | Result |
|---|---|---|
| Nothing | Yes | 🟡 Possible Privacy Concern (undisclosed sharing) |
| "We never share / sell…" | Yes | 🔴 Potential Contradiction (High for ad/attribution SDKs) |
| Vague mention | Yes | ⚪ Insufficient Evidence |
| Discloses sharing with partners | Yes | 🟢 No Contradiction |

**Demo:** Click **🌦️ Weather (Hidden Trackers)** in the sidebar. The policy never mentions sharing, but the app bundles AdMob, AppsFlyer and Firebase Analytics. All three are flagged, along with the undisclosed `AD_ID` permission.

**Strongest proof (future work):** Capturing the app's network traffic (mitmproxy) and seeing requests to the tracker's servers. The tool tells the user to do this for each tracker finding.

**Tests:** `test_tracker_with_silent_policy_is_undisclosed_sharing`, `test_tracker_with_sharing_denial_is_contradiction`, `test_tracker_with_disclosed_sharing_is_aligned`, `test_undisclosed_advertising_id_is_a_concern`, and the 12 tests in `test_tracker_detector.py`.

---

## Q2. What is the actual relationship between an app's Terms and Conditions and its permissions?

**Short answer:** They play three different roles and connect through specific clauses.

| Document | What it is |
|---|---|
| **Terms & Conditions** | The user contract: rules of use, liability, rights over content |
| **Privacy Policy** | The disclosure of what data is collected and why |
| **Permissions** | What the app is technically able to access on the phone |

The T&C do not grant permissions — Android does that. But T&C clauses change **what happens to data once a permission gives access to it**. The tool now detects five kinds of clause:

| Clause type | Example | How it relates to permissions |
|---|---|---|
| Incorporates the Privacy Policy | "By using the app you agree to our Privacy Policy" | Makes the policy part of the contract, so a policy-vs-permission gap becomes a contract gap |
| Licence over user content | "You grant us a worldwide, royalty-free licence to photos you upload" | Raises the stakes of Camera / Storage / Microphone permissions — the company can reuse what they capture |
| Blanket consent to collection | "You consent to the collection and processing of your data" | Tries to cover every permission with one click |
| Third-party sharing / advertising | "We may share usage data with advertising partners" | Data from any permission may leave the app |
| Unilateral change right | "We may modify these terms at any time without notice" | Any promise limiting permission use can be withdrawn later |

**What we built:** An optional **Terms & Conditions** text box. The Results page lists each clause found, but only those relevant to the permissions this app actually requests.

**Demo:** The Weather demo case includes T&C. The T&C admit sharing with advertising partners even though the privacy policy says nothing about it — a disclosure placed in the wrong document.

**Scope note:** Our core analysis is still privacy policy versus permissions. T&C analysis is a supporting layer, not a replacement.

**Tests:** 16 tests in `test_terms_analyzer.py`, and `test_terms_content_licence_is_linked_to_camera_permission`.

---

## Q3. Just because an app requests a permission, how can we conclude that it collects data?

**Short answer:** We cannot, and the tool no longer implies that we can. A permission proves **capability**, not **collection**.

**What was wrong before:** The tool's wording already said this, but its scoring did not follow its own wording. A permission that was only *declared* cost the same score penalty as if the data had been proven to be collected.

**What we built — an evidence ladder.** Every finding now records how strong its evidence is:

| Level | Evidence | What it proves | How to obtain | Score weight |
|---|---|---|---|---|
| 1 | Declared in manifest / store listing | The app *can ask* for the data | apktool, aapt, Play Store | 0.5 |
| 2 | Code present in the APK | The app *contains code* that uses it | jadx, Androguard, tracker SDK list | 0.75 |
| 3 | Observed at runtime | That code *actually runs* | Frida hooking, permission prompt | 0.9 |
| 4 | Data seen leaving the device | Data is *actually sent* | mitmproxy, PCAP capture | 1.0 |

**Trust score formula (now explained on screen):**

```
Score = 100 − Σ (penalty × evidence weight)
penalty: contradiction = 30, undisclosed = 15, not justified by stated purpose = 10
```

- **Why these penalties:** A contradiction is a false statement, so it costs twice an omission. An unjustified permission is a data-minimisation issue, so it costs least.
- **Why these weights:** A declared permission is only half the evidence of observed transmission.

The Results page shows the line-by-line breakdown, so every point lost has a stated reason.

**Correct conclusion language:**
- Levels 1–3: "potential contradiction" or "possible concern".
- Level 4 only: "collection confirmed".

**Tests:** `test_declared_permission_costs_less_than_observed_transmission`, `test_runtime_source_implies_runtime_level`.

---

## Q4. How can we identify loopholes in our project?

**Short answer:** Through adversarial testing. We wrote deliberately tricky policy sentences, ran them through the analyzer, and checked for wrong results:
- **False positives:** contradictions flagged that are not real.
- **False negatives:** real problems that were missed.

Each loophole found became a permanent regression test, so it cannot silently come back.

**Loopholes found and fixed:**

| # | Loophole | Example | Before | After |
|---|---|---|---|---|
| 1 | "Do not sell" read as "do not collect" | "We collect your location for navigation, but we do not sell it." | 🔴 False contradiction | 🟢 Collection disclosed; sharing denied |
| 2 | "Contact us" read as the contacts permission | "If you have questions, contact us at help@…" | Hid an undisclosed `READ_CONTACTS` | 🟡 Correctly flagged as undisclosed |
| 3 | The word "use" counted as disclosure | "You can use the microphone button." | 🟢 Wrongly "disclosed" | ⚪ Ambiguous |
| 4 | Negation applied to the whole sentence | "We record audio when you hold the voice button, but we never share it." | 🔴 False denial | 🟢 Collection disclosed |
| 5 | Conditional denial treated as a flat denial | "We do not track your location without your active initiation." | 🔴 False contradiction | 🟢 Consent-gated |
| 6 | User sharing read as third-party sharing (found while building the new sharing check) | "You can share photos with the community." | Would have counted as sharing disclosure | Ignored for sharing |
| 7 | Common permissions unknown; `INTERNET` penalised as "unnecessary" | `AD_ID`, `INTERNET`, SMS permissions | Treated as unknown and low-risk | Known, with a correct risk level |

**Effect on the bundled sample cases:**

| Sample | Before | After | Why |
|---|---|---|---|
| FTC Brightest Flashlight (real deceptive app) | 3 contradictions | **3 contradictions** | Real contradictions still caught ✅ |
| Torch (contradictory demo) | 4 contradictions | **4 contradictions** | Unchanged ✅ |
| Telegram | 1 contradiction | **0 contradictions** | Loophole 5 — "without your active initiation" is consent, not denial |
| WhatsApp demo | 2 contradictions | **0 contradictions** | Loophole 1 — "We do not sell your contacts" is not a collection denial. Loophole 5 — "when you are not using location services" is conditional |
| NaviRoute (transparent demo) | 0 contradictions | **0 contradictions** | Unchanged ✅ |

The README already claimed Telegram gives 0 contradictions. Before this fix the code actually produced 1, and now it matches the README.

**Ongoing method for finding loopholes:**
1. **Adversarial sentences** for each analyzer rule: negation, conditions, contrast words ("but", "however") and look-alike words ("contact us").
2. **Known-answer cases:** real apps with a known verdict (the FTC flashlight case) must keep their result after every change.
3. **Regression tests:** every fixed loophole becomes a test in `tests/test_loophole_fixes.py`.

### Known limitations (honest answer if asked)

- **Rules, not understanding:** the analyzer is rule-based (regular expressions), not full language understanding. Unusual phrasing can still be misread; the optional LLM mode is meant to help here.
- **English-only** policies.
- **Evidence levels 2–4 are supplied by the user.** The tool does not yet decompile APKs (Androguard) or capture traffic (mitmproxy) by itself.
- **Limited tracker list:** the tracker list covers 23 well-known SDKs, not the full Exodus Privacy database.
- **Coarse conditional denials:** a denial such as "not in the background" is treated as conditional. A future version should compare it specifically against `ACCESS_BACKGROUND_LOCATION`.
- **No Play Store comparison yet:** comparing against the Play Store "Data safety" form is not implemented.

---

## How to Verify

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -q          # expected: 122 passed
streamlit run app.py         # then click "🌦️ Weather (Hidden Trackers)" in the sidebar
```

## Files Changed

| File | Status |
|---|---|
| `src/analysis/tracker_detector.py` | **New** — tracker SDK signatures and matching |
| `src/analysis/terms_analyzer.py` | **New** — T&C clause detection |
| `src/analysis/rule_analyzer.py` | Changed — sharing category, clause-level negation, loophole fixes |
| `src/analysis/contradiction_detector.py` | Changed — evidence levels, weighted score, tracker and T&C integration |
| `src/permissions/permission_db.py` | Changed — sharing domain; 5 new permissions |
| `app.py` | Changed — new optional inputs, result panels, demo button |
| `sample_data/sample_tracker_app.json` | **New** — fictional demo app with hidden trackers |
| `tests/test_loophole_fixes.py`, `test_tracker_detector.py`, `test_terms_analyzer.py` | **New** — 51 tests |
| `README.md` | Fixed merge-conflict lines and test counts; documented evidence levels |
