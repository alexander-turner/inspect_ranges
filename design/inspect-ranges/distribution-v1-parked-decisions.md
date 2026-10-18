# Distribution v1: decisions parked for the user

*Accumulated during the unattended run per the AFK protocol: each entry states the question, the recommendation, and the safe interim behavior in force while the decision waits. Entries are appended as they arise and marked when decided; none blocks the slice that parked it.*

## 1. The scoped org token breaks public Docker Hub pulls on the logged-in host (found live, 2026-10-18)

**The fact, measured on this devbox:** with the org access token logged in (scoped to `meridianlabsai/ir-dist-test` only), `docker pull registry:2` fails with `authentication required - access token has insufficient scopes`. Docker sends the stored docker.io credential for every docker.io pull, public images included, and the registry rejects an insufficiently-scoped token outright instead of falling back to anonymous. Any public-image pull on this box (the range image's `ubuntu:24.04` base on a rebuild, `registry:2` for batteries) fails while the org token is the stored credential. Worked around in the slice-2 probe by backing up the credential, logging out for the one pull, and restoring.

**The question:** keep the narrowly-scoped org token (safest if leaked, but public pulls on this box need the logout/restore dance), or switch the devbox login to a personal access token at Read & Write (account-wide, public pulls work, revoke after the arc)?

**Recommendation:** keep the org token; the arc's own registry client never uses docker's credential for public pulls (it only authenticates where it must), and docker-CLI public pulls are rare enough here to tolerate the dance. Either way this lands in the slice-6 docs as fleet guidance: a deployment host logged in with a scoped token must expect public docker-CLI pulls to fail, which is one more argument for mirroring the public org into the deployment registry.

**Interim behavior in force:** org token stays logged in; batteries that need a public image pull do the backup/logout/pull/restore sequence explicitly.
