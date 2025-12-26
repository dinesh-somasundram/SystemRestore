\# System Restore (Windows) — CLI + GUI



A Windows utility to manage \*\*System Restore\*\*:

\- Checks whether System Restore is enabled

\- Enables System Restore (optional shadow storage sizing)

\- Lists restore points (Seq #, Date/Time, Description)

\- Creates restore points (\*\*blocked if a restore point was created within 24 hours\*\*)

\- Deletes restore points by \*\*Sequence Number\*\* (internally maps to VSS shadow copy; 3600s tolerance)



Includes:

\- Interactive CLI (`sys\_rest\_cli.py`)

\- Minimal Tkinter GUI (`sys\_rest\_gui.py`)

\- Core library (`system\_restore.py`)



---



\## Screenshots



\### GUI

!\[GUI](screenshots/gui.png)



\### CLI

!\[CLI](screenshots/cli.png)



---



\## Run from source



\### CLI

```bash

python sys\_rest\_cli.py



GUI



pythonw sys\_rest\_gui.py



Notes



&nbsp;   Requires Administrator privileges (auto-elevates).



&nbsp;   Deletion correlates restore points to VSS shadow copies using nearest timestamp within 3600 seconds.



Project structure



&nbsp;   system\_restore.py — core logic (Windows)



&nbsp;   sys\_rest\_cli.py — interactive CLI



&nbsp;   sys\_rest\_gui.py — Tkinter GUI



Hire me



I build Python automation tools (Windows utilities, data/report automation, API integrations).



Contact: s\_dinesh@outlook.com





After you paste it:

1\) Create a folder named `screenshots`

2\) Save two images as:

&nbsp;  - `screenshots/gui.png`

&nbsp;  - `screenshots/cli.png`



Then tell me \*\*“done”\*\* and we’ll create the GitHub repo + push files.



\*\*a.\*\* Public or private repo?  

\*\*b.\*\* Do you want to include the `.exe` in GitHub Releases later?



You said:

can you give it to be as one single block? Say as text? thaat I can copy an paste?

Code Copilot said:



Absolutely — here it is as one single plain-text block you can copy/paste directly into README.md:



\# System Restore (Windows) — CLI + GUI



A Windows utility to manage \*\*System Restore\*\*:

\- Checks whether System Restore is enabled

\- Enables System Restore (optional shadow storage sizing)

\- Lists restore points (Seq #, Date/Time, Description)

\- Creates restore points (\*\*blocked if a restore point was created within 24 hours\*\*)

\- Deletes restore points by \*\*Sequence Number\*\* (internally maps to VSS shadow copy; 3600s tolerance)



Includes:

\- Interactive CLI (`sys\_rest\_cli.py`)

\- Minimal Tkinter GUI (`sys\_rest\_gui.py`)

\- Core library (`system\_restore.py`)



---



\## Screenshots



\### GUI

!\[GUI](screenshots/gui.png)



\### CLI

!\[CLI](screenshots/cli.png)



---



\## Run from source



CLI:

```bash

python sys\_rest\_cli.py



GUI:



pythonw sys\_rest\_gui.py



Notes



&nbsp;   Requires Administrator privileges (auto-elevates).



&nbsp;   Deletion correlates restore points to VSS shadow copies using nearest timestamp within 3600 seconds.



Project structure



&nbsp;   system\_restore.py — core logic (Windows)



&nbsp;   sys\_rest\_cli.py — interactive CLI



&nbsp;   sys\_rest\_gui.py — Tkinter GUI



Hire me



I build Python automation tools (Windows utilities, data/report automation, API integrations).



Contact: YOUR\_EMAIL\_OR\_LINK\_HERE





Next:

1\) Create folder `screenshots`

2\) Save two screenshots as:

\- `screenshots/gui.png`

\- `screenshots/cli.png`



When that’s done, tell me \*\*“README + screenshots done”\*\* and we’ll push to GitHub.



\*\*a.\*\* Public or private repo?  

\*\*b.\*\* Do you want to upload the `.exe` in GitHub Releases later?

