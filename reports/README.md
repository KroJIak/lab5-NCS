# Lab 5 DevSecOps report

Repository: [Retr0-46/lab5-NCS](https://github.com/Retr0-46/lab5-NCS)

This folder holds the reports for the DevSecOps lab. The base application is PyGoat, a Python app with deliberate vulnerabilities in it. The work of the lab is to put security checks into the pipeline that builds it.

## Pipeline

The pipeline is in `.github/workflows/main.yml`. It has three jobs and runs on every push.

| Job | Tool | What it does |
|---|---|---|
| `sast_scan` | Bandit | Reads the Python code and looks for dangerous patterns |
| `image_scan` | Docker Scout | Builds the Docker image and looks for CVEs in it |
| `dast_scan` | OWASP ZAP | Starts PyGoat and tests the running app |

All three jobs end in a red mark, and that is the correct result. Bandit finds real problems in the code, Scout finds real problems in the base image, and ZAP finds real problems in the running application. A green run here would mean the scanners stopped working.

## Task 3, the DAST report

The summary is in [reports/dast/README.md](dast/README.md). The raw ZAP report is next to it in HTML, JSON and Markdown.

The first working run is [45147326709](https://github.com/KroJIak/lab5-NCS/actions/runs/45147326709).

## Task 4, one vulnerability per team member

Every member of the group picked a different finding from the Bandit scan and wrote about it on their own.

| Member | Finding | Classification | Report |
|---|---|---|---|
| Lil_ZaChill | `eval()` on form input | CWE-95, Eval Injection | [report](task4/report.md) |
| Mark | File read outside the blog folder | CWE-22, Path Traversal | [report](path_traversal/report.md) |
| KroJIak | `pickle.loads()` on form input | CWE-502, Unsafe Deserialization | [report](task4/pickle_deserialization_report.md) |

The Bandit scan of the whole repository gives 53 findings, 30 Medium and 23 High. The raw output for the pickle rule is in [task4/bandit-b301.txt](task4/bandit-b301.txt).

## Bonus task, patching the code

The report is in [reports/bonus/bonus_report.md](bonus/bonus_report.md).

The pickle finding was fixed in the application code. Pickle was replaced with JSON signed with HMAC-SHA256, so the server checks the signature before it uses any value from the request. Three tests cover the normal flow, the attempt to change the admin flag and a pickle payload.

The Bandit scan goes from 53 findings to 52, and the B301 findings go from 2 to 1. The numbers are in [bonus/bandit-before-after.txt](bonus/bandit-before-after.txt).

## Three bugs in the pipeline

All three of them were found while writing the reports, and every one of them stopped a scan from producing its report.

**The DAST job never reached ZAP.** The readiness step waited for HTTP 200, but PyGoat answers `/` with a 302 redirect to the login page. The check could never pass, so the step ran out of retries and ZAP was skipped in every run. The check now accepts any status below 500.

**The image scan could not authenticate.** The error was `could not authenticate: user githubactions not entitled to use Docker Scout`. Docker Scout checks the Docker Hub entitlement of the account it finds in the runner credential store. On a public runner the only credential there is the GitHub token, stored under the name `githubactions`, and that account has no Docker Scout subscription. The job now logs in to Docker Hub first.

**The ZAP report was lost.** The action version the job used, v0.12.0, uploads the report with an old version of the artifacts library, and the upload failed with `Create Artifact Container failed: The artifact name zap_scan is not valid`. The scan itself worked, so only the report file was missing. The action was upgraded to v0.15.0.

The Docker Hub login needs the `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD` repository secrets. A free Docker Hub account is enough. Until somebody with admin rights on the repository adds them, the image scan stops with a message that says exactly that.

## Runs

| Run | What it shows |
|---|---|
| [45008357700](https://github.com/Retr0-46/lab5-NCS/actions/runs/45008357700) | The state before the fixes. ZAP was skipped and Scout could not authenticate |
| [45147326709](https://github.com/KroJIak/lab5-NCS/actions/runs/45147326709) | The first run where ZAP produced a report |
| [45148621442](https://github.com/KroJIak/lab5-NCS/actions/runs/45148621442) | The run with the clearer message about the missing secrets |

## Sources

- [Bandit documentation](https://bandit.readthedocs.io/en/1.9.4/)
- [Docker Scout action](https://github.com/docker/scout-action)
- [OWASP ZAP baseline scan action](https://github.com/zaproxy/action-baseline)
- [MITRE CWE](https://cwe.mitre.org/)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
