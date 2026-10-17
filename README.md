# VaultSense

**Vault Sense** is AI fraud detection that runs inside IBM Z's secure enclave. It scores every transaction in milliseconds and explains each alert, and customer data never leaves encrypted memory.

## Project overview

- **Real-time scoring:** every transaction gets a fraud score within milliseconds.
- **Explainable alerts:** each flagged transaction comes with the reasons it was flagged, so analysts can act quickly.
- **Confidential by design:** the model runs inside IBM Z's secure enclave, so customer data stays in encrypted memory the whole time.

## Team

| GitHub | Role |
| --- | --- |
| [@swatichander251](https://github.com/swatichander251) | Repo owner |
| [@silverND088](https://github.com/silverND088) | Collaborator |
| [@bnigam21](https://github.com/bnigam21) | Collaborator |
| [@afreenshaik77](https://github.com/afreenshaik77) | Collaborator |
| [@nchouhan17](https://github.com/nchouhan17) | Collaborator |

## Repository layout

```
VaultSense/
├── src/              # Python source code
├── notebooks/        # Jupyter notebooks for exploration and experiments
├── data/             # Local datasets (git-ignored, never committed)
├── requirements.txt  # Python dependencies
└── README.md
```

## Getting started

### 2. Set up the Python virtual environment

**macOS / Linux**

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

When you add a dependency, install it and then record it in `requirements.txt` with an exact version (e.g. `pandas==2.2.3`), and commit the change.

## Team server

| | |
| --- | --- |
| Host | `148.100.109.192` |
| Login | `ssh <your-username>@148.100.109.192` |
| Shared project folder | `/srv/project` (a clone of this repo) |
| Shared venv | `/srv/project/venv` |

- The server only accepts **SSH keys**, not passwords. Each teammate logs in with their own Linux account and the SSH key they sent to the admin.
- Everyone on the team is in the `team` group, which can read and write `/srv/project`.
- If your private key isn't in the default location, use `ssh -i ~/.ssh/<your-key> <your-username>@148.100.109.192`.

Optional shortcut: add this to `~/.ssh/config` on your laptop, then just run `ssh vaultsense`:

```
Host vaultsense
    HostName 148.100.109.192
    User <your-username>
    IdentityFile ~/.ssh/<your-key>
```

### Using the shared venv on the server

```bash
cd /srv/project
source venv/bin/activate
pip install -r requirements.txt
```

## Workflow

**Write code on your laptop, push it to GitHub, then `git pull` on the server.**

1. **On your laptop:** get the latest code, then make your changes.
   ```bash
   git pull
   # ...edit code...
   git add <files>
   git commit -m "Describe your change"
   git push
   ```
2. **On the server:** update the shared copy and run it.
   ```bash
   ssh <your-username>@148.100.109.192
   cd /srv/project
   git pull
   source venv/bin/activate
   pip install -r requirements.txt   # only if dependencies changed
   ```

Ground rules:

- **Don't edit code directly in `/srv/project`.** The server copy only pulls from GitHub, and its deploy key is read-only, so it can't push.
- **Never commit data or secrets.** `data/`, `.env`, `venv/`, `*.pem` and SSH keys are already git-ignored. Keep datasets in `data/` on your laptop or on the server.
- Pull before you start work and push often, so you run into fewer merge conflicts.
