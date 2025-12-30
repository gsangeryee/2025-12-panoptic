
(cantina)
[S-#] TITLE (Root Cause -> Impact)

## Summary
A short summary of the issue, keep it brief.

## Finding Description
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.

Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.

## Impact Explanation
Elaborate on why you've chosen a particular impact assessment.

## Likelihood Explanation (cantina)
Explain how likely this is to occur and why.

## Proof of Concept
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.

## Recommendation
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.

(CodeHawks)
[S-#] TITLE (Root Cause + Impact)

**Description:** 

The follow block of code is responsible for the issue.

```javascript
@> // @audit - 

```

**Impact:** 

**Proof of Concept:**

<details>
<summary>Proof of Code</summary>
Place the following into `xxxx.t.sol`

```javascript

```
</details>

**Recommended Mitigation:** 

```diff
- remove this code
+ add this code
```

